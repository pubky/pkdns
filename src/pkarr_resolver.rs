use std::{error::Error, sync::{Arc, Mutex}};

use pkarr::{
    dns::{Packet, ResourceRecord},
    PkarrClient, PublicKey,
};

use crate::pkarr_cache::PkarrPacketTtlCache;

/**
 * Pkarr resolver with cache.
 */
#[derive(Clone)]
pub struct PkarrResolver {
    client: PkarrClient,
    cache: Arc<Mutex<PkarrPacketTtlCache>>,
}

impl PkarrResolver {
    pub fn new(max_cache_ttl: u64) -> Self {
        Self {
            client: PkarrClient::new(),
            cache: Arc::new(Mutex::new(PkarrPacketTtlCache::new(max_cache_ttl))),
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

    fn resolve_pubkey_respect_cache(&mut self, pubkey: &PublicKey) -> Option<Vec<u8>> {
        let mut cache = self.cache.lock().unwrap();
        let cached_opt = cache.get(pubkey);
        if cached_opt.is_some() {
            let reply_bytes = cached_opt.unwrap();
            return Some(reply_bytes)
        };


        let packet_option = self.client.resolve(pubkey.clone());
        if packet_option.is_none() {
            return None;
        };
        let reply_bytes = packet_option.unwrap().packet().build_bytes_vec().unwrap();
        cache.add(pubkey.clone(), reply_bytes);
        cache.get(pubkey)
    }

    /**
     * Resolves a domain with pkarr.
     */
    pub fn resolve(
        &mut self,
        query: &Vec<u8>
    ) -> std::prelude::v1::Result<Vec<u8>, Box<dyn Error>> {
        let request = Packet::parse(query)?;

        let question_opt = request.questions.first();
        if question_opt.is_none() {
            return Err("Missing question".into());
        }
        let question = question_opt.unwrap();
        let labels = question.qname.get_labels();

        let raw_pubkey = labels.last().unwrap().to_string();
        let parsed_option = Self::parse_pkarr_uri(&raw_pubkey);
        if parsed_option.is_none() {
            return Err("Invalid pkarr pubkey".into());
        }
        let pubkey = parsed_option.unwrap();

        let packet_option = self.resolve_pubkey_respect_cache(&pubkey);
        if packet_option.is_none() {
            return Err("No pkarr packet found for pubkey".into());
        }
        let packet = packet_option.unwrap();
        let packet = Packet::parse(&packet).unwrap();

        let matching_records: Vec<ResourceRecord<'_>> = packet.answers.iter()
            .filter(|record| record.match_qclass(question.qclass) && record.match_qtype(question.qtype) && record.name == question.qname)
            .map(|record| record.clone())
            .collect();

        let mut reply = request.into_reply();
        reply.answers = matching_records;
        // println!("Pkarr reply {:?} with {} ms", reply, start.elapsed().as_millis());
        let reply_bytes: Vec<u8> = reply.build_bytes_vec()?;
        Ok(reply_bytes)
    }
}

#[cfg(test)]
mod tests {
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

    fn publish_record() {
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
        let result = client.publish(&signed_packet);
        result.expect("Should have published.");
    }

    #[test]
    fn query_domain() {
        publish_record();

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
        
        let mut resolver = PkarrResolver::new(0);
        let result = resolver.resolve(&query.build_bytes_vec().unwrap());
        assert!(result.is_ok());
        let reply_bytes = result.unwrap();
        let reply = Packet::parse(&reply_bytes).unwrap();
        assert_eq!(reply.id(), query.id());
        assert_eq!(reply.answers.len(), 1);
        let answer = reply.answers.first().unwrap();
        assert_eq!(answer.name.to_string(), name.to_string());
        assert_eq!(answer.rdata.type_code(), pkarr::dns::TYPE::A);
    }

    #[test]
    fn query_pubkey() {
        publish_record();

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
        let mut resolver = PkarrResolver::new(0);
        let result = resolver.resolve(&query.build_bytes_vec().unwrap());
        assert!(result.is_ok());
        let reply_bytes = result.unwrap();
        let reply = Packet::parse(&reply_bytes).unwrap();
        assert_eq!(reply.id(), query.id());
        assert_eq!(reply.answers.len(), 1);
        let answer = reply.answers.first().unwrap();
        assert_eq!(answer.name.to_string(), name.to_string());
        assert_eq!(answer.rdata.type_code(), pkarr::dns::TYPE::A);
    }

    #[test]
    fn query_invalid_pubkey() {
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
        let mut resolver = PkarrResolver::new(0);
        let result = resolver.resolve(&query.build_bytes_vec().unwrap());
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
}
