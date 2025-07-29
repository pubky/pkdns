use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use crate::resolution::DnsSocket;
use pkarr::dns::{
    rdata::{self, RData},
    Name, Packet, PacketFlag, Question, ResourceRecord, QTYPE, RCODE, TYPE,
};

/**
 * Handles all possible ways on how to resolve a query into a reply.
 * Does not support forwards, only recursive queries.
 * Max CNAME depth == 1.
 * Uses a query to transforms a pkarr reply into an regular reply
 */
pub async fn resolve_query<'a>(pkarr_packet: &Packet<'a>, query: &Packet<'a>) -> Vec<u8> {
    let question = query.questions.first().unwrap(); // Has at least 1 question based on previous checks.
    let pkarr_reply = resolve_question(pkarr_packet, question).await;
    let pkarr_reply = Packet::parse(&pkarr_reply).unwrap();

    let mut reply = query.clone().into_reply();
    reply.answers = pkarr_reply.answers;
    reply.additional_records = pkarr_reply.additional_records;
    reply.name_servers = pkarr_reply.name_servers;

    reply.build_bytes_vec_compressed().unwrap()
}

/**
 * Resolves a question by filtering the pkarr packet and creating a corresponding reply.
 */
async fn resolve_question<'a>(pkarr_packet: &Packet<'a>, question: &Question<'a>) -> Vec<u8> {
    let mut reply = Packet::new_reply(0);

    let direct_matchs = direct_matches(pkarr_packet, &question.qname, &question.qtype);
    reply.answers.extend(direct_matchs.clone());

    if reply.answers.is_empty() {
        // Not found. Maybe it is a cname?
        let cname_matches = resolve_cname_for(pkarr_packet, question);
        reply.answers.extend(cname_matches);
    };

    if reply.answers.is_empty() {
        // Not found. Maybe we have a name server?
        reply.name_servers = find_nameserver(pkarr_packet, &question.qname);

        // Add all glued A/AAAA records to the additional section
        for ns in reply.name_servers.iter() {
            if let RData::NS(val) = &ns.rdata {
                let name = &val.0;
                let matches_a = direct_matches(pkarr_packet, name, &QTYPE::TYPE(TYPE::A));
                let matches_aaaa = direct_matches(pkarr_packet, name, &QTYPE::TYPE(TYPE::AAAA));
                let merged_matches: Vec<_> = matches_a.into_iter().chain(matches_aaaa.into_iter()).collect();
                reply.additional_records.extend(merged_matches);
            };
        }
    };

    reply.build_bytes_vec_compressed().unwrap()
}

/**
 * Resolve a cnames for a given. Only goes to max 1 depth. CNAME always needs to point to a A/AAAA record.
 */
fn resolve_cname_for<'a>(pkarr_packet: &Packet<'a>, question: &Question<'a>) -> Vec<ResourceRecord<'a>> {
    let cname_matches = direct_matches(pkarr_packet, &question.qname, &QTYPE::TYPE(TYPE::CNAME));

    let additional_data: Vec<ResourceRecord<'_>> = cname_matches
        .iter()
        .flat_map(|cname| {
            let cname_content = if let RData::CNAME(rdata::CNAME(cname_pointer)) = &cname.rdata {
                cname_pointer
            } else {
                panic!("Should be cname");
            };
            let matches = direct_matches(pkarr_packet, cname_content, &question.qtype);
            matches
        })
        .collect();

    let mut result = vec![];
    result.extend(cname_matches);
    result.extend(additional_data);

    result
}

/**
 * Resolve direct qname and qtype record matches.
 */
fn direct_matches<'a>(pkarr_packet: &Packet<'a>, qname: &Name<'a>, qtype: &QTYPE) -> Vec<ResourceRecord<'a>> {
    let matches: Vec<ResourceRecord<'_>> = pkarr_packet
        .answers
        .iter()
        .filter(|record| record.name == *qname && record.match_qtype(*qtype))
        .cloned()
        .collect();
    matches
}

/**
 * Find nameserver for given qname.
 */
fn find_nameserver<'a>(pkarr_packet: &Packet<'a>, qname: &Name<'a>) -> Vec<ResourceRecord<'a>> {
    let matches: Vec<ResourceRecord<'_>> = pkarr_packet
        .answers
        .iter()
        .filter(|record| {
            record.match_qtype(QTYPE::TYPE(TYPE::NS)) && (qname.is_subdomain_of(&record.name) || record.name == *qname)
        })
        .cloned()
        .collect();
    matches
}

// /**
//  * Resolve name server ip
//  */
// async fn resolve_ns_ip<'a>(ns_name: &Name<'a>) -> Option<Vec<SocketAddr>> {
//     let ns_question = Question::new(
//         ns_name.clone(),
//         QTYPE::TYPE(TYPE::A),
//         pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
//         false,
//     );
//     let mut query = Packet::new_query(0);
//     query.questions.push(ns_question);
//     query.set_flags(PacketFlag::RECURSION_DESIRED);
//     let query = query.build_bytes_vec_compressed().unwrap();
//
//     let reply = socket.query_me(&query, None).await;
//     let reply = Packet::parse(&reply).ok()?;
//     if reply.answers.len() == 0 {
//         return None;
//     };
//
//     let addresses: Vec<SocketAddr> = reply
//         .answers
//         .into_iter()
//         .filter_map(|record| match record.rdata {
//             RData::A(data) => {
//                 let ip = Ipv4Addr::from(data.address);
//                 Some(SocketAddr::new(ip.into(), 53))
//             }
//             RData::AAAA(data) => {
//                 let ip = Ipv6Addr::from(data.address);
//                 Some(SocketAddr::new(ip.into(), 53))
//             }
//             _ => None,
//         })
//         .collect();
//
//     Some(addresses)
// }
//
// /**
//  * Resolves the question with a single ns redirection.
//  */
// async fn resolve_with_ns<'a>(
//     question: &Question<'a>,
//     name_servers: &Vec<ResourceRecord<'a>>,
// ) -> Option<Vec<u8>> {
//     if name_servers.len() == 0 {
//         return None;
//     }
//
//     let ns_names: Vec<Name<'_>> = name_servers
//         .iter()
//         .filter_map(|record| {
//             if let RData::NS(data) = record.clone().rdata {
//                 Some(data.0)
//             } else {
//                 None
//             }
//         })
//         .collect();
//
//     let ns_name = ns_names.first().unwrap();
//     let addresses = resolve_ns_ip(ns_name).await?;
//     let addr = addresses.first().unwrap();
//
//     let mut query = Packet::new_query(0);
//     query.questions.push(question.clone());
//     query.set_flags(PacketFlag::RECURSION_DESIRED);
//     let query = query.build_bytes_vec_compressed().unwrap();
//
//     socket.forward(&query, addr, Duration::from_millis(1000)).await.ok()
// }

/**
 * Constructs a reply indicating that the query got rate limited.
 */
pub fn create_domain_not_found_reply(query_id: u16) -> Vec<u8> {
    let mut reply = Packet::new_reply(query_id);
    *reply.rcode_mut() = RCODE::NameError;
    reply.build_bytes_vec_compressed().unwrap()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::app_context::AppContext;
    use crate::resolution::{pkd::PkarrResolver, DnsSocket};
    use pkarr::dns::{rdata::RData, Question};
    use pkarr::{
        dns::{Name, Packet, ResourceRecord},
        Keypair, PublicKey,
    };

    use super::{resolve_query, resolve_question};

    fn example_pkarr_reply() -> (Vec<u8>, PublicKey) {
        // pkarr.normalize_names makes sure all names end with the pubkey.
        // @ is invalid and just syntactic sugar on top of pkarr.normalize_names
        // No ending dot.

        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let pubkey_z32 = keypair.to_z32();
        let mut packet = Packet::new_reply(0);

        let name = Name::new(&pubkey_z32).unwrap();
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let answer1 = ResourceRecord::new(name.clone(), pkarr::dns::CLASS::IN, 100, RData::A(ip.into()));
        packet.answers.push(answer1);

        let name = format!("pknames.p2p.{pubkey_z32}");
        let name = Name::new(&name).unwrap();
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let answer1 = ResourceRecord::new(name.clone(), pkarr::dns::CLASS::IN, 100, RData::A(ip.into()));
        packet.answers.push(answer1);

        let name = format!("www.pknames.p2p.{pubkey_z32}");
        let name = Name::new(&name).unwrap();
        let data = format!("pknames.p2p.{pubkey_z32}");
        let data = Name::new(&data).unwrap();
        let answer3 = ResourceRecord::new(
            name.clone(),
            pkarr::dns::CLASS::IN,
            100,
            RData::CNAME(pkarr::dns::rdata::CNAME(data)),
        );
        packet.answers.push(answer3);

        let name = format!("other.{pubkey_z32}");
        let name = Name::new(&name).unwrap();
        let data = "my.ns.example.com".to_string();
        let data = Name::new(&data).unwrap();
        let answer4 = ResourceRecord::new(
            name.clone(),
            pkarr::dns::CLASS::IN,
            100,
            RData::NS(pkarr::dns::rdata::NS(data)),
        );
        packet.answers.push(answer4);

        (packet.build_bytes_vec_compressed().unwrap(), pubkey)
    }

    #[tokio::test]
    async fn simple_a_question() {
        let (pkarr_packet, pubkey) = example_pkarr_reply();
        let pkarr_packet = Packet::parse(&pkarr_packet).unwrap();
        let pubkey_z32 = pubkey.to_z32();

        let name = format!("pknames.p2p.{pubkey_z32}");
        let name = Name::new(&name).unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let question = Question::new(
            name.clone(),
            qtype,
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            false,
        );

        let reply = resolve_question(&pkarr_packet, &question).await;
        let reply = Packet::parse(&reply).unwrap();
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.additional_records.len(), 0);
        assert_eq!(reply.name_servers.len(), 0);
        let answer = reply.answers.first().unwrap();
        assert_eq!(answer.name, name);
        assert!(answer.match_qtype(qtype));
    }

    #[tokio::test]
    async fn a_question_with_cname() {
        let (pkarr_packet, pubkey) = example_pkarr_reply();
        let pkarr_packet = Packet::parse(&pkarr_packet).unwrap();
        let pubkey_z32 = pubkey.to_z32();

        let name = format!("www.pknames.p2p.{pubkey_z32}");
        let name = Name::new(&name).unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let question = Question::new(
            name.clone(),
            qtype,
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            false,
        );

        let context = AppContext::test();
        let mut socket = DnsSocket::new(&context).await.unwrap();
        let reply = resolve_question(&pkarr_packet, &question).await;
        let reply = Packet::parse(&reply).unwrap();
        assert_eq!(reply.answers.len(), 2);
        assert_eq!(reply.additional_records.len(), 0);
        assert_eq!(reply.name_servers.len(), 0);

        let answer1 = reply.answers.first().unwrap();
        assert_eq!(answer1.name, name);
        assert!(answer1.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::CNAME)));

        let answer2 = reply.answers.get(1).unwrap();
        assert_eq!(answer2.name.to_string(), format!("pknames.p2p.{pubkey_z32}"));
        assert!(answer2.match_qtype(qtype));
    }

    #[tokio::test]
    async fn a_question_with_ns() {
        let (pkarr_packet, pubkey) = example_pkarr_reply();
        let pkarr_packet = Packet::parse(&pkarr_packet).unwrap();
        let pubkey_z32 = pubkey.to_z32();

        let name = format!("other.{pubkey_z32}");
        let name = Name::new(&name).unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let question = Question::new(
            name.clone(),
            qtype,
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            false,
        );
        let context = AppContext::test();
        let socket = DnsSocket::new(&context).await.unwrap();
        let reply = resolve_question(&pkarr_packet, &question).await;
        let reply = Packet::parse(&reply).unwrap();
        assert_eq!(reply.answers.len(), 0);
        assert_eq!(reply.additional_records.len(), 0);
        assert_eq!(reply.name_servers.len(), 1);

        let ns1 = reply.name_servers.first().unwrap();
        assert_eq!(ns1.name, name);
        assert!(ns1.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::NS)));
    }

    #[tokio::test]
    async fn a_question_with_ns_subdomain() {
        let (pkarr_packet, pubkey) = example_pkarr_reply();
        let pkarr_packet = Packet::parse(&pkarr_packet).unwrap();
        let pubkey_z32 = pubkey.to_z32();

        let name = format!("sub.other.{pubkey_z32}");
        let name = Name::new(&name).unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let question = Question::new(
            name.clone(),
            qtype,
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            false,
        );

        let context = AppContext::test();
        let mut socket = DnsSocket::new(&context).await.unwrap();
        let reply = resolve_question(&pkarr_packet, &question).await;
        let reply = Packet::parse(&reply).unwrap();
        assert_eq!(reply.answers.len(), 0);
        assert_eq!(reply.additional_records.len(), 0);
        assert_eq!(reply.name_servers.len(), 1);

        let ns1 = reply.name_servers.first().unwrap();
        assert_eq!(ns1.name.to_string(), format!("other.{pubkey_z32}"));
        assert!(ns1.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::NS)));
    }

    #[tokio::test]
    async fn simple_a_query() {
        let (pkarr_packet, _pubkey) = example_pkarr_reply();
        let pkarr_packet = Packet::parse(&pkarr_packet).unwrap();

        let mut query = Packet::new_query(0);
        query.questions = vec![Question::new(
            Name::new("pknames.p2p").unwrap(),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            false,
        )];

        let context = AppContext::test();
        let socket = DnsSocket::new(&context).await.unwrap();
        let _reply = resolve_query(&pkarr_packet, &query);
    }
}
