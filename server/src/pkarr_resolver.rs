

use std::{net::SocketAddr, sync::Arc};

use any_dns::DnsSocket;
use anyhow::anyhow;
use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::{bootstrap_nodes::MainlineBootstrapResolver, packet_lookup::resolve_query, pkarr_cache::{CachedSignedPacket, PkarrPacketLruCache}};
use pkarr::{dns::Packet, mainline::dht::DhtSettings, PkarrClient, PkarrClientAsync, PublicKey};



/**
 * Pkarr resolver with cache.
 */
#[derive(Clone)]
pub struct PkarrResolver {
    client: PkarrClientAsync,
    cache: PkarrPacketLruCache,
    /**
     * Locks to use to update pkarr packets. This avoids concurrent updates.
     */
    lock_map: Arc<DashMap<PublicKey, Arc<Mutex<()>>>>
}

impl PkarrResolver {

    /**
     * Resolves the DHT boostrap nodes with the forward server.
     */
    fn resolve_bootstrap_nodes(forward_dns_server: Option<SocketAddr>) -> Vec<String> {
        let mut dns_server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        if let Some(val) = forward_dns_server {
            dns_server = val;
        };
        tracing::debug!("Connecting to the DNS forward server {}. Hold on...", dns_server.to_string());
        let addrs = MainlineBootstrapResolver::get_addrs(dns_server); 
        if addrs.is_err() {
            let err = addrs.unwrap_err();
            tracing::error!("{}", err);
            tracing::error!("Connecting to the DNS forward server failed. Couldn't resolve the DHT bootstrap nodes. Is the DNS forward server active?");
            panic!("Resolving bootstrap nodes failed. {}", err);
        }
        tracing::debug!("Success. DNS forward server reply received.");
        addrs.unwrap()
    }

    pub async fn new(forward_dns_server: Option<SocketAddr>) -> Self {
        let addrs = Self::resolve_bootstrap_nodes(forward_dns_server);
        let mut settings = DhtSettings::default();
        settings.bootstrap = Some(addrs);
        let client = PkarrClient::builder()
        .minimum_ttl(0).maximum_ttl(0) // Disable Pkarr caching
        .dht_settings(settings) // Use resolved bootstrap node
        .build().unwrap();
        Self {
            client: client.as_async(),
            cache: PkarrPacketLruCache::new(None),
            lock_map: Arc::new(DashMap::new())
        }
    }

    fn parse_pkarr_uri(uri: &str) -> Option<PublicKey> {
        let decoded = zbase32::decode_full_bytes_str(uri);
        if decoded.is_err() {
            return None;
        };
        let decoded = decoded.unwrap();
        if decoded.len() != 32 {
            return None;
        };
        let trying: Result<PublicKey, _> = uri.try_into();
        trying.ok()
    }

    async fn resolve_pubkey_respect_cache(&mut self, pubkey: &PublicKey) -> Option<Vec<u8>> {
        if let Some(cached) = self.cache.get(pubkey).await {
            tracing::debug!("Pkarr packet [{pubkey}] found in cache. Expires in {}s", cached.ttl_expires_in_s());
            if cached.is_ttl_expired() {
                tracing::debug!("Initiate background refresh for [{pubkey}].");
                let mut me = self.clone();
                let public_key = pubkey.clone();
                tokio::spawn(async move {
                    me.lookup_dht_without_cache(public_key).await
                });
            };
            let bytes = cached.packet.packet().build_bytes_vec().expect("Expect valid pkarr packet from cache");
            return Some(bytes);
        };

        tracing::trace!("Lookup [{pubkey}] on the DHT.");
        let packet = self.lookup_dht_without_cache(pubkey.clone()).await;
        if packet.is_none() {
            return None;
        };
        let signed_packet = packet.unwrap().packet;
        let reply_bytes = signed_packet.packet().build_bytes_vec_compressed().unwrap();
        self.cache.add(signed_packet).await;
        Some(reply_bytes)
    }

    /**
     * Lookup DHT to pull pkarr packet. Will not check the cache first but store any new value in the cache. Returns cached value if lookup fails.
     */
    async fn lookup_dht_without_cache(&mut self, pubkey: PublicKey) -> Option<CachedSignedPacket> {
        let mutex = self.lock_map.entry(pubkey.clone()).or_insert_with(|| Arc::new(Mutex::new(())));
        let _guard = mutex.lock().await;

        if let Some(cache) = self.cache.get(&pubkey).await {
            if !cache.is_ttl_expired() {
                // Value got updated in the meantime while aquiring the lock.
                tracing::trace!("Refresh for [{pubkey}] not needed. Value got updated in the meantime.");
                return Some(cache);
            }
        }

        let packet_option = self.client.resolve(&pubkey).await;
        if packet_option.is_err() {
            let err = packet_option.unwrap_err();
            tracing::error!("DHT lookup for [{pubkey}] errored. {err}");

            return self.cache.get(&pubkey).await
        };

        let signed_packet = packet_option.unwrap();
        if signed_packet.is_none() {
            tracing::debug!("DHT lookup for [{pubkey}] failed. Nothing found.");
            return self.cache.get(&pubkey).await
        };

        tracing::trace!("Refreshed cache for [{pubkey}].");
        let new_packet = signed_packet.unwrap();
        Some(self.cache.add(new_packet).await)
    }

    /**
     * Resolves a domain with pkarr.
     */
    pub async fn resolve(&mut self, query: &Vec<u8>, socket: &mut DnsSocket) -> std::prelude::v1::Result<Vec<u8>, anyhow::Error> {
        let request = Packet::parse(query)?;

        let question_opt = request.questions.first();
        if question_opt.is_none() {
            tracing::debug!("DNS packet doesn't include a question.");
            return Err(anyhow!("Missing question"));
        }
        let question = question_opt.unwrap();
        let labels = question.qname.get_labels();
        if labels.len() == 0 {
            tracing::debug!("DNS packet question with no domain.");
            return Err(anyhow!("No label in question."));
        };

        tracing::debug!("New query: {} {:?}", question.qname.to_string(), question.qtype);

        let tld = labels.last().unwrap().to_string();
        let parsed_option = Self::parse_pkarr_uri(&tld);
        if parsed_option.is_none() {
            tracing::debug!("TLD .{tld} is not a pkarr key. Fallback to ICANN. ");
            return Err(anyhow!("Invalid pkarr pubkey"));
        }
        let pubkey = parsed_option.unwrap();
        let packet_option = self.resolve_pubkey_respect_cache(&pubkey).await;
        if packet_option.is_none() {
            tracing::info!("No pkarr packet found on the DHT [{tld}].");
            return Err(anyhow!("No pkarr packet found for pubkey"));
        }
        let pkarr_packet = packet_option.unwrap();
        let pkarr_packet = Packet::parse(&pkarr_packet).unwrap();
        tracing::trace!("Pkarr packet resolved [{tld}].");
        let reply = resolve_query(&pkarr_packet, &request, socket).await;
        Ok(reply)
    }


    
}

#[cfg(test)]
mod tests {
    use any_dns::{EmptyHandler, HandlerHolder};
    use pkarr::{
        dns::{Name, Packet, Question, ResourceRecord}, Keypair, Settings, SignedPacket
    };
    use chrono::{DateTime, Utc};

    // use simple_dns::{Name, Question, Packet};
    use super::*;
    use std::net::Ipv4Addr;
    use zbase32;

    trait SignedPacketTimestamp {
        fn chrono_timestamp(&self) -> DateTime<Utc>;
    }
    
    impl SignedPacketTimestamp for SignedPacket {
        fn chrono_timestamp(&self) -> DateTime<Utc> {
            let timestamp = self.timestamp() / 1_000_000;
            let timestamp = DateTime::from_timestamp((timestamp as u32).into(), 0).unwrap();
            timestamp
        }
    }

    fn get_test_keypair() -> Keypair {
        // pk:cb7xxx6wtqr5d6yqudkt47drqswxk57dzy3h7qj3udym5puy9cso
        let secret = "6kfe1u5jyqxg644eqfgk1cp4w9yjzwq51rn11ftysuo6xkpc64by";
        let seed = zbase32::decode_full_bytes_str(secret).unwrap();
        let slice: &[u8; 32] = &seed[0..32].try_into().unwrap();
        let keypair = Keypair::from_secret_key(slice);
        keypair
    }

    async fn publish_record() {
        let keypair = get_test_keypair();
        // let uri = keypair.to_uri_string();
        // println!("Publish packet with pubkey {}", uri);

        let mut packet = Packet::new_reply(0);
        let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();
        let record = ResourceRecord::new(
            Name::new("pknames.p2p").unwrap(),
            pkarr::dns::CLASS::IN,
            100,
            pkarr::dns::rdata::RData::A(ip.try_into().unwrap()),
        );
        packet.answers.push(record);
        let record = ResourceRecord::new(
            Name::new(".").unwrap(),
            pkarr::dns::CLASS::IN,
            100,
            pkarr::dns::rdata::RData::A(ip.try_into().unwrap()),
        );
        packet.answers.push(record);
        let signed_packet = SignedPacket::from_packet(&keypair, &packet).unwrap();

        let client = PkarrClient::new(Settings::default()).unwrap();
        let result = client.publish(&signed_packet);
        result.expect("Should have published.");
    }

    async fn get_dnssocket() -> DnsSocket {
        let handler = HandlerHolder::new(EmptyHandler::new());
        DnsSocket::new("127.0.0.1:20384".parse().unwrap(), "8.8.8.8:53".parse().unwrap(), handler).await.unwrap()
    }

    #[tokio::test]
    async fn query_domain() {
        publish_record().await;

        let keypair = get_test_keypair();
        let domain = format!("pknames.p2p.{}", keypair.to_z32());
        let name = Name::new(&domain).unwrap();
        let mut query = Packet::new_query(0);
        let question = Question::new(
            name.clone(),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            true,
        );
        query.questions.push(question);

        let mut resolver = PkarrResolver::new(None).await;
        let mut socket = get_dnssocket().await;
        let result = resolver.resolve(&query.build_bytes_vec_compressed().unwrap(), &mut socket).await;
        assert!(result.is_ok());
        let reply_bytes = result.unwrap();
        let reply = Packet::parse(&reply_bytes).unwrap();
        assert_eq!(reply.id(), query.id());
        assert_eq!(reply.answers.len(), 1);
        let answer = reply.answers.first().unwrap();
        assert_eq!(answer.name.to_string(), name.to_string());
        assert_eq!(answer.rdata.type_code(), pkarr::dns::TYPE::A);
    }

    #[tokio::test]
    async fn query_pubkey() {
        publish_record().await;

        let keypair = get_test_keypair();
        let domain = keypair.to_z32();
        let name = Name::new(&domain).unwrap();
        let mut query = Packet::new_query(0);
        let question = Question::new(
            name.clone(),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            true,
        );
        query.questions.push(question);
        let mut resolver = PkarrResolver::new(None).await;
        let mut socket = get_dnssocket().await;
        let result = resolver.resolve(&query.build_bytes_vec_compressed().unwrap(), &mut socket).await;
        assert!(result.is_ok());
        let reply_bytes = result.unwrap();
        let reply = Packet::parse(&reply_bytes).unwrap();
        assert_eq!(reply.id(), query.id());
        assert_eq!(reply.answers.len(), 1);
        let answer = reply.answers.first().unwrap();
        assert_eq!(answer.name.to_string(), name.to_string());
        assert_eq!(answer.rdata.type_code(), pkarr::dns::TYPE::A);
    }

    #[tokio::test]
    async fn query_invalid_pubkey() {
        let domain = "invalid_pubkey";
        let name = Name::new(&domain).unwrap();
        let mut query = Packet::new_query(0);
        let question = Question::new(
            name.clone(),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            true,
        );
        query.questions.push(question);
        let mut resolver = PkarrResolver::new(None).await;
        let mut socket = get_dnssocket().await;
        let result = resolver.resolve(&query.build_bytes_vec_compressed().unwrap(), &mut socket).await;
        assert!(result.is_err());
        // println!("{}", result.unwrap_err());
    }

    #[test]
    fn pkarr_parse() {
        let domain = "cb7xxx6wtqr5d6yqudkt47drqswxk57dzy3h7qj3udym5puy9cso";
        let decoded = zbase32::decode_full_bytes_str(domain);
        // assert!(decoded.is_err());
        let decoded = decoded.unwrap();
        println!("{:?}", decoded);
        if decoded.len() != 32 {
            println!("wrong length");
            return;
        }
        let trying: Result<PublicKey, _> = domain.try_into();
        assert!(trying.is_err());
    }

    #[tokio::test]
    async fn pkarr_invalid_packet1() {
        let pubkey = PkarrResolver::parse_pkarr_uri("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy").unwrap();

        let mut resolver = PkarrResolver::new(None).await;
        let _result = resolver.resolve_pubkey_respect_cache(&pubkey).await;
        // assert!(result.is_some());
    }

    #[tokio::test]
    async fn pkarr_invalid_packet2() {
        let pubkey = PkarrResolver::parse_pkarr_uri("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy").unwrap();
        let client = PkarrClient::new(Settings::default()).unwrap();
        let signed_packet = client.resolve(&pubkey).unwrap().unwrap();
        println!("Timestamp {}", signed_packet.chrono_timestamp());
        let reply_bytes = signed_packet.packet().build_bytes_vec_compressed().unwrap();
        Packet::parse(&reply_bytes).unwrap();
    }

    #[test]
    fn pkarr_invalid_packet3() {
        let keypair = Keypair::random();
        let pubkey_z32 = keypair.to_z32();

        // Construct reply with single CNAME record.
        let mut packet = Packet::new_reply(0);

        let name = Name::new("www.pknames.p2p").unwrap();
        let data = format!("pknames.p2p.{pubkey_z32}");
        let data = Name::new(&data).unwrap();
        let answer3 = ResourceRecord::new(
            name.clone(),
            simple_dns::CLASS::IN,
            100,
            simple_dns::rdata::RData::CNAME(simple_dns::rdata::CNAME(data)),
        );
        packet.answers.push(answer3);

        // Sign packet
        let signed_packet = SignedPacket::from_packet(&keypair, &packet).unwrap();

        // Serialize and parse again
        let reply_bytes = signed_packet.packet().build_bytes_vec().unwrap();
        Packet::parse(&reply_bytes).unwrap(); // Fail
    }
}
