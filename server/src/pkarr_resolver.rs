use any_dns::DnsSocket;
use anyhow::anyhow;

use crate::{packet_lookup::resolve_query, pkarr_cache::PkarrPacketTtlCache};
use chrono::{DateTime, Utc};
use pkarr::{dns::Packet, PkarrClient, PublicKey, SignedPacket};

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

/**
 * Pkarr resolver with cache.
 */
#[derive(Clone)]
pub struct PkarrResolver {
    client: PkarrClient,
    cache: PkarrPacketTtlCache,
}

impl PkarrResolver {
    pub async fn new(max_cache_ttl: u64) -> Self {
        Self {
            client: PkarrClient::new(),
            cache: PkarrPacketTtlCache::new(max_cache_ttl).await,
        }
    }

    pub fn parse_pkarr_uri(uri: &str) -> Option<PublicKey> {
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
        let cached_opt = self.cache.get(pubkey).await;
        if cached_opt.is_some() {
            let reply_bytes = cached_opt.unwrap();
            return Some(reply_bytes);
        };

        let packet_option = self.client.resolve(pubkey.clone()).await;
        if packet_option.is_none() {
            return None;
        };
        let signed_packet = packet_option.unwrap();
        let reply_bytes = signed_packet.packet().build_bytes_vec_compressed().unwrap();
        self.cache.add(pubkey.clone(), reply_bytes.clone()).await;
        Some(reply_bytes)
    }

    /**
     * Resolves a domain with pkarr.
     */
    pub async fn resolve(&mut self, query: &Vec<u8>, socket: &mut DnsSocket) -> std::prelude::v1::Result<Vec<u8>, anyhow::Error> {
        let request = Packet::parse(query)?;

        let question_opt = request.questions.first();
        if question_opt.is_none() {
            return Err(anyhow!("Missing question"));
        }
        let question = question_opt.unwrap();
        let labels = question.qname.get_labels();
        if labels.len() == 0 {
            return Err(anyhow!("No label in question.qname."));
        };

        let raw_pubkey = labels.last().unwrap().to_string();
        let parsed_option = Self::parse_pkarr_uri(&raw_pubkey);
        if parsed_option.is_none() {
            return Err(anyhow!("Invalid pkarr pubkey"));
        }
        let pubkey = parsed_option.unwrap();

        let packet_option = self.resolve_pubkey_respect_cache(&pubkey).await;
        if packet_option.is_none() {
            return Err(anyhow!("No pkarr packet found for pubkey"));
        }
        let pkarr_packet = packet_option.unwrap();
        let pkarr_packet = Packet::parse(&pkarr_packet).unwrap();
        let reply = resolve_query(&pkarr_packet, &request, socket).await;

        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use any_dns::{EmptyHandler, HandlerHolder};
    use pkarr::{
        dns::{Name, Packet, Question, ResourceRecord},
        Keypair, SignedPacket,
    };

    // use simple_dns::{Name, Question, Packet};
    use super::*;
    use std::net::Ipv4Addr;
    use zbase32;

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

        let client = PkarrClient::new();
        let result = client.publish(&signed_packet).await;
        result.expect("Should have published.");
    }

    async fn get_dnssocket() -> DnsSocket {
        let handler = HandlerHolder::new(EmptyHandler::new());
        DnsSocket::new("127.0.0.1:20384".parse().unwrap(), "8.8.8.8:53".parse().unwrap(), handler, false).await.unwrap()
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

        let mut resolver = PkarrResolver::new(0).await;
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
        let mut resolver = PkarrResolver::new(0).await;
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
        let mut resolver = PkarrResolver::new(0).await;
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

        let mut resolver = PkarrResolver::new(0).await;
        let _result = resolver.resolve_pubkey_respect_cache(&pubkey).await;
        // assert!(result.is_some());
    }

    #[tokio::test]
    async fn pkarr_invalid_packet2() {
        let pubkey = PkarrResolver::parse_pkarr_uri("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy").unwrap();
        let client = PkarrClient::new();
        let signed_packet = client.resolve(pubkey).await.unwrap();
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
