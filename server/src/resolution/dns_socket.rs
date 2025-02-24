#![allow(unused)]
use crate::{
    config::get_global_config,
    resolution::{helpers::replace_packet_id, pkd::CustomHandlerError},
};
use rand::Rng;
use tracing_subscriber::fmt::format;

use super::{
    dns_packets::{ParsedPacket, ParsedQuery},
    pending_request::{PendingRequest, PendingRequestStore},
    pkd::{PkarrResolver, ResolverSettings, TopLevelDomain},
    query_id_manager::QueryIdManager,
    rate_limiter::{RateLimiter, RateLimiterBuilder},
    response_cache::IcannLruCache,
};
use pkarr::dns::{
    rdata::{RData, A, AAAA, NS},
    Packet, PacketFlag, SimpleDnsError, QTYPE, RCODE,
};
use std::{
    hash::{Hash, Hasher},
    num::NonZeroU64,
    thread::current,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};
use std::{
    net::{SocketAddrV4, SocketAddrV6},
    num,
};
use tokio::{
    net::UdpSocket,
    sync::{oneshot, RwLock},
    task::JoinHandle,
};
use tracing::Level;

/// Any error related to receiving and sending DNS packets on the UDP socket.
#[derive(thiserror::Error, Debug)]
pub enum DnsSocketError {
    #[error("Dns packet parse error: {0}")]
    Parse(#[from] SimpleDnsError),

    #[error(transparent)]
    IO(#[from] tokio::io::Error),

    #[error("Timeout. No answer received from forward server.")]
    ForwardTimeout(#[from] tokio::time::error::Elapsed),

    #[error("Rx receive error. {0}")]
    RxReceiedErr(#[from] oneshot::error::RecvError),
}

/**
 * DNS UDP socket
 */
#[derive(Debug, Clone)]
pub struct DnsSocket {
    socket: Arc<UdpSocket>,
    pending: PendingRequestStore,
    pkarr_resolver: PkarrResolver,
    icann_fallback: SocketAddr,
    id_manager: QueryIdManager,
    rate_limiter: Arc<RateLimiter>,
    disable_any_queries: bool,
    icann_cache: IcannLruCache,
    max_recursion_depth: u8,
}

impl DnsSocket {
    /// Random local socket addr
    /// 0.0.0.0:{49152..=65535}
    /// Used for testing
    fn random_local_socket() -> SocketAddr {
        let mut rng = rand::thread_rng();
        let random_port: u32 = rng.gen_range(49152..=65535);
        let socket_str = format!("0.0.0.0:{random_port}");
        socket_str.parse().unwrap()
    }

    /// Default dns socket but with a random listening port. Made for testing.
    pub async fn default_random_socket() -> tokio::io::Result<Self> {
        let listening = Self::random_local_socket();
        let icann_resolver: SocketAddr = "8.8.8.8:53".parse().unwrap();
        DnsSocket::new(
            listening,
            icann_resolver,
            999,
            999,
            999,
            999,
            0,
            0,
            NonZeroU64::new(1).unwrap(),
            1,
            Some(TopLevelDomain::new("key".to_string())),
            5,
        )
        .await
    }

    // Create a new DNS socket
    pub async fn new(
        listening: SocketAddr,
        icann_resolver: SocketAddr,
        max_queries_per_ip_per_second: u32,
        max_queries_per_ip_burst: u32,
        max_dht_queries_per_ip_per_second: u32,
        max_dht_queries_per_ip_burst: u32,
        min_ttl: u64,
        max_ttl: u64,
        pkarr_cache_mb: NonZeroU64,
        icann_cache_mb: u64,
        top_level_domain: Option<TopLevelDomain>,
        max_recursion_depth: u8,
    ) -> tokio::io::Result<Self> {
        let socket = UdpSocket::bind(listening).await?;
        let limiter = RateLimiterBuilder::new()
            .max_per_second(max_queries_per_ip_per_second)
            .burst_size(max_queries_per_ip_burst);

        let config = get_global_config();

        let resolver_settings = ResolverSettings {
            max_ttl,
            min_ttl,
            cache_mb: pkarr_cache_mb.into(),
            forward_dns_server: icann_resolver.clone(),
            max_dht_queries_per_ip_per_second,
            max_dht_queries_per_ip_burst,
            top_level_domain: top_level_domain,
        };
        let pkarr_resolver = PkarrResolver::new(resolver_settings).await;
        Ok(Self {
            socket: Arc::new(socket),
            pending: PendingRequestStore::new(),
            pkarr_resolver: pkarr_resolver,
            icann_fallback: icann_resolver,
            id_manager: QueryIdManager::new(),
            rate_limiter: Arc::new(limiter.build()),
            disable_any_queries: config.dns.disable_any_queries,
            icann_cache: IcannLruCache::new(icann_cache_mb, min_ttl, max_ttl),
            max_recursion_depth,
        })
    }

    fn is_recursion_available(&self) -> bool {
        self.max_recursion_depth >= 1
    }

    // Send message to address
    pub async fn send_to(&self, buffer: &[u8], target: &SocketAddr) -> tokio::io::Result<usize> {
        self.socket.send_to(buffer, target).await
    }

    /// Starts the receive loop in the background.
    /// Returns the JoinHandle to stop the loop again.
    pub fn start_receive_loop(&self) -> oneshot::Sender<()> {
        let mut cloned = self.clone();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut cancel = rx;
            loop {
                tokio::select! {
                    _ = &mut cancel => {
                        tracing::trace!("Stop UDP receive loop.");
                        break;
                    }
                    result = cloned.receive_datagram() => {
                        if let Err(err) = result {
                            tracing::error!("Error while trying to receive. {err}");
                        }
                    }
                }
            }
        });
        tx
    }

    async fn receive_datagram(&mut self) -> Result<(), DnsSocketError> {
        let mut buffer = [0; 1024];
        let (size, from) = self.socket.recv_from(&mut buffer).await?;

        let mut data = buffer.to_vec();
        if data.len() > size {
            data.drain((size + 1)..data.len());
        }

        let packet = ParsedPacket::new(data)?;

        let packet_id = packet.id();
        let pending = self.pending.remove_by_forward_id(&packet_id, &from);
        if pending.is_some() {
            tracing::trace!("Received response from forward server. Send back to client.");
            let query = pending.unwrap();
            query.tx.send(packet.into()).unwrap();
            return Ok(());
        };

        if packet.is_reply() {
            tracing::debug!(
                "Received reply without an associated query {:?}. forward_id={packet_id} Ignore.",
                packet
            );
            return Ok(());
        };

        // New query
        let query_parser: Result<ParsedQuery, _> = packet.try_into();
        if let Err(e) = query_parser {
            tracing::debug!("Failed to parse query {from}. id={packet_id}. {e} Drop.");
            return Ok(());
        };
        let query = query_parser.unwrap();
        if self.disable_any_queries {
            if query.is_any_type() {
                tracing::debug!("Received ANY type question from {from}. id={packet_id}. Drop.");
                return Ok(());
            }
        }

        let mut socket = self.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            let reply = socket.query_me_recursively_with_log(&query, Some(from.ip())).await;
            socket.send_to(&reply, &from).await;
        });

        Ok(())
    }

    /// Queries recursively with a byte query. If the query can't be parsed, return a server fail.
    pub async fn query_me_recursively_raw(&mut self, query: Vec<u8>, from: Option<IpAddr>) -> Vec<u8> {
        let packet = ParsedPacket::new(query);
        if let Err(e) = packet {
            tracing::trace!("Failed to parse query {e}. Drop");
            return vec![];
        }
        let packet = packet.unwrap();
        match ParsedQuery::try_from(packet.clone()) {
            Ok(parsed) => self.query_me_recursively_with_log(&parsed, from).await,
            Err(e) => packet.create_server_fail_reply(),
        }
    }

    /// Queries recursively with a log.
    pub async fn query_me_recursively_with_log(&mut self, query: &ParsedQuery, from: Option<IpAddr>) -> Vec<u8> {
        let start = Instant::now();
        let reply = self.query_me_recursively(&query, from).await;
        tracing::debug!("{query} processed within {}ms.", start.elapsed().as_millis());
        reply
    }

    /// Queries recursively. This is the main query function of this socket.
    async fn query_me_recursively(&mut self, query: &ParsedQuery, from: Option<IpAddr>) -> Vec<u8> {
        // Rate limit check
        if let Some(ip) = &from {
            if self.rate_limiter.check_is_limited_and_increase(ip) {
                tracing::trace!("Rate limited {}. query_id={}", query.packet.id(), ip);
                return query.packet.create_refused_reply();
            };
        }

        // Based on https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.2

        let client_query = query;
        let client_query_data: Vec<u8> = client_query.packet.clone().into();
        let mut client_reply = Packet::parse(&client_query_data).unwrap().into_reply();
        if self.is_recursion_available() {
            client_reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
        } else {
            client_reply.remove_flags(PacketFlag::RECURSION_AVAILABLE);
        }
        let mut next_name_server: Option<SocketAddr> = None; // Name server to target. If none, falls back to default and DHT
        let mut next_raw_query: Vec<u8> = client_query_data.clone();
        for i in 0..self.max_recursion_depth {
            let current_query = ParsedQuery::new(next_raw_query.clone()).unwrap();
            tracing::trace!(
                "Recursive lookup {i}/{} NS:{next_name_server:?} - {current_query}",
                self.max_recursion_depth,
            );
            // println!("Recursive lookup {i}/{} NS:{next_name_server:?} - {:?}", self.max_recursion_depth, current_query.question());
            let reply = self.query_me_once(&current_query, from.clone(), next_name_server).await;
            next_name_server = None; // Reset target DNS
            let parsed_reply = Packet::parse(&reply).expect("Reply must be a valid dns packet.");

            if !self.is_recursion_available() {
                tracing::trace!("Recursion not available return.");
                return reply;
            }
            if !client_query.is_recursion_desired() {
                tracing::trace!("Recursion not desired. return.");
                return reply;
            }

            if parsed_reply.rcode() != RCODE::NoError {
                // Downstream server returned error.
                tracing::debug!(
                    "Downstream server returned error {:?} during recursion. Query: {current_query}",
                    parsed_reply.rcode()
                );
                *client_reply.rcode_mut() = parsed_reply.rcode();
                return client_reply.build_bytes_vec().unwrap();
            }

            if parsed_reply.answers.len() == 0 && parsed_reply.name_servers.len() == 0 {
                // No answers and NS received.
                tracing::warn!("Empty reply {current_query}");
                return client_reply.build_bytes_vec().unwrap();
            }

            let matching_answers_names: Vec<&pkarr::dns::ResourceRecord<'_>> = parsed_reply
                .answers
                .iter()
                .filter(|answer| answer.name == current_query.question().qname)
                .collect();

            // Check for direct matches
            let matching_answers_names_and_qtype: Vec<&pkarr::dns::ResourceRecord<'_>> = matching_answers_names
                .clone()
                .into_iter()
                .filter(|answer| answer.match_qtype(current_query.question().qtype))
                .collect();

            if matching_answers_names_and_qtype.len() > 0 {
                // We found answers matching the name and the type.
                // Copy everything over and return.
                tracing::trace!("Recursion final answer found.");

                for answer in parsed_reply.answers {
                    client_reply.answers.push(answer.into_owned());
                }
                for additional in parsed_reply.additional_records {
                    client_reply.additional_records.push(additional.into_owned());
                }
                for ns in parsed_reply.name_servers {
                    client_reply.name_servers.push(ns.into_owned());
                }
                return client_reply.build_bytes_vec().unwrap();
            }

            // No direct answer matches
            // Look for a CNAME
            let matching_cname = matching_answers_names
                .clone()
                .into_iter()
                .find(|answer| answer.match_qtype(QTYPE::TYPE(pkarr::dns::TYPE::CNAME)));

            if let Some(rr) = matching_cname {
                // Matching CNAME
                tracing::trace!("Recursion: Matching CNAME {rr:?}");
                if let pkarr::dns::rdata::RData::CNAME(val) = &rr.rdata {
                    // Clone CNAME answer to main reply.
                    client_reply.answers.push(rr.clone().into_owned());
                    // Replace question with the content of the cname
                    let mut question = current_query.question().clone().into_owned();
                    question.qname = val.0.clone();
                    let mut next_query = current_query.packet.parsed().clone();
                    next_query.questions = vec![question];
                    next_query.set_flags(PacketFlag::RECURSION_DESIRED);
                    next_raw_query = next_query.build_bytes_vec().unwrap();
                    continue;
                } else {
                    panic!("CNAME match failure. Shouldnt happen.")
                };
            };

            // Look for NS referals
            let ns_matches: Vec<&pkarr::dns::ResourceRecord<'_>> = parsed_reply
                .name_servers
                .iter()
                .filter(|rr| {
                    current_query.question().qname.is_subdomain_of(&rr.name)
                        || current_query.question().qname == rr.name
                })
                .collect();
            if ns_matches.is_empty() {
                // No NS matches either; Copy additional and return main reply.
                tracing::trace!("No direct and no ns matches");
                for additional in parsed_reply.additional_records {
                    client_reply.additional_records.push(additional.into_owned());
                }
                return client_reply.build_bytes_vec().unwrap();
            }

            tracing::trace!("NS matches. {parsed_reply:?}");
            let found_name_server = parsed_reply.name_servers.iter().find_map(|ns| {
                if let RData::NS(NS(ns_name)) = &ns.rdata {
                    let ns_a_record = parsed_reply.additional_records.iter().find(|rr| {
                        rr.name == *ns_name && rr.match_qtype(QTYPE::TYPE(pkarr::dns::TYPE::A))
                            || rr.match_qtype(QTYPE::TYPE(pkarr::dns::TYPE::AAAA))
                    });
                    if ns_a_record.is_none() {
                        return None;
                    }
                    let ns_a_record = ns_a_record.unwrap();
                    let glued_ns_socket: SocketAddr = match ns_a_record.rdata {
                        RData::A(A { address }) => {
                            let ip = Ipv4Addr::from_bits(address);
                            let socket = SocketAddrV4::new(ip, 53);
                            socket.into()
                        }
                        RData::AAAA(AAAA { address }) => {
                            let ip = Ipv6Addr::from_bits(address);
                            let socket = SocketAddrV6::new(ip, 53, 0, 0);
                            socket.into()
                        }
                        _ => panic!("Prefiltered, shouldnt happen"),
                    };
                    return Some(glued_ns_socket);
                } else {
                    return None;
                }
            });
            if let Some(socket) = &found_name_server {
                tracing::trace!("Found glued nameserver {socket}");
                next_name_server = found_name_server;
                continue;
            };

            // Unhandled NS response. Probably SOA. Return
            for ns in parsed_reply.name_servers.iter() {
                client_reply.name_servers.push(ns.clone().into_owned());
            }
            return client_reply.build_bytes_vec().unwrap();
        }

        // Max recursion exceeded
        tracing::debug!("Max recursion exceeded. {query}");
        client_query.packet.create_server_fail_reply()
    }

    /// Query this DNS for data once without recursion.
    /// from: Client ip used for rate limiting. None disables rate limiting
    /// target_dns: dns server to query. None falls back to the default fallback DNS
    async fn query_me_once(
        &mut self,
        query: &ParsedQuery,
        from: Option<IpAddr>,
        target_dns: Option<SocketAddr>,
    ) -> Vec<u8> {
        // Only try the DHT first if no target_dns is manually specified.
        if let None = &target_dns {
            tracing::trace!("Trying to resolve the query with the custom handler.");
            let result = self.pkarr_resolver.resolve(&query, from).await;
            if result.is_ok() {
                tracing::trace!("Custom handler resolved the query.");
                // All good. Handler handled the query
                return result.unwrap();
            }

            match result.unwrap_err() {
                CustomHandlerError::Unhandled => {
                    tracing::trace!("Custom handler rejected the query. {query}");
                }
                CustomHandlerError::Failed(err) => {
                    tracing::error!("Internal error {query}: {}", err);
                    return query.packet.create_server_fail_reply();
                }
                CustomHandlerError::RateLimited(ip) => {
                    tracing::error!("IP is rate limited {query}: {}", ip);
                    return query.packet.create_refused_reply();
                }
            };
        }

        // Forward to ICANN
        let dns_socket = target_dns.unwrap_or(self.icann_fallback.clone());
        match self
            .forward_to_icann(&query.packet.clone().into(), dns_socket, Duration::from_secs(5))
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                tracing::warn!("Forwarding dns query failed. {e} {query}");
                query.packet.create_server_fail_reply()
            }
        }
    }

    /// Send dns request to configured forward server
    pub async fn forward(
        &mut self,
        query: &Vec<u8>,
        to: &SocketAddr,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsSocketError> {
        let packet = Packet::parse(&query)?;
        let (tx, rx) = oneshot::channel::<Vec<u8>>();
        let forward_id = self.id_manager.get_next(to);
        let original_id = packet.id();
        tracing::trace!("Fallback to forward server {to:?}. orignal_id={original_id} forward_id={forward_id}");
        let request = PendingRequest {
            original_query_id: original_id,
            forward_query_id: forward_id,
            sent_at: Instant::now(),
            to: to.clone(),
            tx,
        };

        let query = packet.build_bytes_vec_compressed()?;
        let query = replace_packet_id(&query, forward_id)?;

        self.pending.insert(request);
        self.send_to(&query, to).await?;

        // Wait on response
        let reply = tokio::time::timeout(timeout, rx).await??;
        let reply = replace_packet_id(&reply, original_id)?;

        Ok(reply)
    }

    /// Forward query to icann
    pub async fn forward_to_icann(
        &mut self,
        query: &Vec<u8>,
        dns_server: SocketAddr,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsSocketError> {
        // Check cache first before forwarding
        if let Ok(opt_item) = self.icann_cache.get(query).await {
            if let Some(item) = opt_item {
                let query_packet = Packet::parse(query)?;
                let new_response = replace_packet_id(&item.response, query_packet.id())?;
                return Ok(new_response);
            };
        };

        let reply = self.forward(query, &dns_server, timeout).await?;
        // Store response in cache
        if let Err(e) = self.icann_cache.add(query.clone(), reply.clone()).await {
            tracing::warn!("Failed to add icann forward reply to cache. {e}");
        };

        Ok(reply)
    }

    // Extracts the id of the query
    fn extract_query_id(&self, query: &Vec<u8>) -> Result<u16, SimpleDnsError> {
        Packet::parse(query).map(|packet| packet.id())
    }

    /// Create a REFUSED reply
    fn create_refused_reply(query_id: u16) -> Vec<u8> {
        let mut reply = Packet::new_reply(query_id);
        *reply.rcode_mut() = RCODE::Refused;
        reply.build_bytes_vec_compressed().unwrap()
    }

    /// Create SRVFAIL reply
    fn create_server_fail_reply(query_id: u16) -> Vec<u8> {
        let mut reply = Packet::new_reply(query_id);
        *reply.rcode_mut() = RCODE::ServerFailure;
        reply.build_bytes_vec_compressed().unwrap()
    }

    pub async fn default() -> Result<Self, anyhow::Error> {
        let socket = UdpSocket::bind("0.0.0.0:53").await?;
        let config = get_global_config();
        Ok(Self {
            socket: Arc::new(socket),
            pending: PendingRequestStore::new(),
            pkarr_resolver: PkarrResolver::default().await,
            icann_fallback: "8.8.8.8:53".parse().unwrap(),
            id_manager: QueryIdManager::new(),
            rate_limiter: Arc::new(RateLimiterBuilder::new().build()),
            disable_any_queries: config.dns.disable_any_queries,
            icann_cache: IcannLruCache::new(100, config.dns.min_ttl, config.dns.max_ttl),
            max_recursion_depth: 5,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::resolution::dns_packets::ParsedQuery;
    use crate::resolution::pkd::{PkarrResolver, TopLevelDomain};
    use pkarr::dns::rdata::{RData, NS};
    use pkarr::dns::{
        rdata::{A, CNAME},
        Name, Packet, PacketFlag, Question, ResourceRecord, RCODE,
    };
    use pkarr::{Client, Keypair, SignedPacket, Timestamp};
    use std::{
        net::{Ipv4Addr, SocketAddr},
        num::NonZeroU64,
        time::Duration,
    };
    use tracing_test::traced_test;

    use super::DnsSocket;

    async fn publish_domain() {
        // Public key csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto
        let seed = "a3kco17a6mqawd9jewgwijrd64gb1rmrer1zptxgire7buufk3hy";
        let decoded = zbase32::decode_full_bytes_str(seed).unwrap();
        let seed: [u8; 32] = decoded.try_into().unwrap();
        let pair = Keypair::from_secret_key(&seed);
        let pubkey = pair.public_key();
        let seed = pair.to_z32();

        let mut reply = Packet::new_reply(0);
        // Regular ICANN CNAME
        let cname_icann = ResourceRecord::new(
            Name::new("cname-icann").unwrap(),
            pkarr::dns::CLASS::IN,
            300,
            pkarr::dns::rdata::RData::CNAME(CNAME(Name::new("example.com").unwrap().into_owned())),
        );
        reply.answers.push(cname_icann);
        // PKD CNAME
        let cname_pkd = ResourceRecord::new(
            Name::new("cname-pkd").unwrap(),
            pkarr::dns::CLASS::IN,
            300,
            pkarr::dns::rdata::RData::CNAME(CNAME(
                Name::new("csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto")
                    .unwrap()
                    .into_owned(),
            )),
        );
        reply.answers.push(cname_pkd);
        // PKD CNAME that points on itself and therefore causes an infinite loop
        let cname_infinte = ResourceRecord::new(
            Name::new("cname-infinite").unwrap(),
            pkarr::dns::CLASS::IN,
            300,
            pkarr::dns::rdata::RData::CNAME(CNAME(
                Name::new("cname-infinite.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto")
                    .unwrap()
                    .into_owned(),
            )),
        );
        reply.answers.push(cname_infinte);
        // PKD CNAME that points on another PKD CNAME that points on a A
        let cname_pkd2 = ResourceRecord::new(
            Name::new("cname-pkd2").unwrap(),
            pkarr::dns::CLASS::IN,
            300,
            pkarr::dns::rdata::RData::CNAME(CNAME(
                Name::new("cname-pkd.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto")
                    .unwrap()
                    .into_owned(),
            )),
        );
        reply.answers.push(cname_pkd2);
        // Regular A entry that anchors the domain.
        let a = ResourceRecord::new(
            Name::new("").unwrap(),
            pkarr::dns::CLASS::IN,
            300,
            pkarr::dns::rdata::RData::A(A {
                address: Ipv4Addr::new(127, 0, 0, 1).to_bits(),
            }),
        );
        reply.answers.push(a);
        // Define BIND name server for the sub.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto zone.
        let ns = ResourceRecord::new(
            Name::new("ns.sub").unwrap(),
            pkarr::dns::CLASS::IN,
            300,
            pkarr::dns::rdata::RData::A(A {
                address: Ipv4Addr::new(95, 217, 214, 181).to_bits(),
            }),
        );
        reply.answers.push(ns);
        // Delegate sub.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto to the name server.
        let sub = ResourceRecord::new(
            Name::new("sub").unwrap(),
            pkarr::dns::CLASS::IN,
            300,
            pkarr::dns::rdata::RData::NS(NS(Name::new(
                "ns.sub.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto",
            )
            .unwrap())),
        );
        reply.answers.push(sub);
        let signed = SignedPacket::new(&pair, &reply.answers, Timestamp::now()).unwrap();
        let relays: Vec<String> = vec!();
        let client = Client::builder().relays(&relays).unwrap().build().unwrap();
        let _res = client.publish(&signed, None).await;
    }

    /// Create a new dns socket and query recursively.
    async fn resolve_query_recursively(query: Vec<u8>) -> Vec<u8> {
        let mut socket = DnsSocket::default_random_socket().await.unwrap();
        let join_handle = socket.start_receive_loop();
        let parsed_query = ParsedQuery::new(query).unwrap();
        let result = socket.query_me_recursively(&parsed_query, None).await;
        join_handle.send(());
        result
    }

    #[tokio::test]
    async fn recursion_cname_icann() {
        publish_domain().await;

        let mut query = Packet::new_query(0);
        let qname = Name::new("cname-icann.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let raw_reply = resolve_query_recursively(raw_query).await;
        let reply = Packet::parse(&raw_reply).unwrap();
        assert!(reply.answers.len() >= 2);
        let cname = reply.answers.get(0).unwrap();
        assert!(cname.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::CNAME)));
        let a = reply.answers.get(1).unwrap().clone().into_owned();
        assert!(a.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A)));
    }

    #[tokio::test]
    async fn recursion_cname_icann_with_tld() {
        publish_domain().await;

        let mut query = Packet::new_query(0);
        let qname = Name::new("cname-icann.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto.key").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let raw_reply = resolve_query_recursively(raw_query).await;
        let reply = Packet::parse(&raw_reply).unwrap();
        assert!(reply.answers.len() >= 2);
        let cname = reply.answers.get(0).unwrap();
        assert!(cname.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::CNAME)));
        let a = reply.answers.get(1).unwrap().clone().into_owned();
        assert!(a.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A)));
    }

    #[tokio::test]
    async fn recursion_cname_pkd() {
        // Single recursion CNAME
        publish_domain().await;
        let mut query = Packet::new_query(0);
        let qname = Name::new("cname-pkd.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let raw_reply = resolve_query_recursively(raw_query).await;
        let reply = Packet::parse(&raw_reply).unwrap();
        dbg!(&reply);
        assert_eq!(reply.answers.len(), 2);
        let cname = reply.answers.get(0).unwrap();
        assert!(cname.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::CNAME)));
        let a = reply.answers.get(1).unwrap().clone().into_owned();
        assert!(a.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A)));
    }

    #[tokio::test]
    async fn recursion_cname_pkd2() {
        // Double recursion CNAME
        publish_domain().await;

        let mut query = Packet::new_query(0);
        let qname = Name::new("cname-pkd2.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let raw_reply = resolve_query_recursively(raw_query).await;
        let reply = Packet::parse(&raw_reply).unwrap();
        assert_eq!(reply.answers.len(), 3);
        let cname1 = reply.answers.get(0).unwrap();
        assert!(cname1.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::CNAME)));
        let cname2 = reply.answers.get(1).unwrap();
        assert!(cname2.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::CNAME)));
        let a = reply.answers.get(2).unwrap().clone().into_owned();
        assert!(a.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A)));
    }

    #[tokio::test]
    async fn recursion_cname_infinite() {
        // Infinite recursion CNAME
        // Check max recursion depth
        publish_domain().await;

        let mut query = Packet::new_query(0);
        let qname = Name::new("cname-infinite.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let raw_reply = resolve_query_recursively(raw_query).await;
        let reply = Packet::parse(&raw_reply).unwrap();
        assert_eq!(reply.rcode(), RCODE::ServerFailure);
    }

    #[tokio::test]
    async fn recursion_not_found1() {
        // Check if the error is copied to
        publish_domain().await;

        let mut query = Packet::new_query(0);
        let qname = Name::new("osjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let raw_reply = resolve_query_recursively(raw_query).await;
        let reply = Packet::parse(&raw_reply).unwrap();
        // dbg!(&reply);
        assert_eq!(reply.rcode(), RCODE::NameError);
    }

    #[tokio::test]
    async fn recursion_not_found2() {
        publish_domain().await;
        let mut query = Packet::new_query(0);
        let qname = Name::new("yolo.example.com").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let raw_reply = resolve_query_recursively(raw_query).await;
        let reply = Packet::parse(&raw_reply).unwrap();
        assert_eq!(reply.rcode(), RCODE::NameError);
    }

    #[tokio::test]
    async fn recursion_ns_pkd() {
        // Single recursion with a delegated zone with an external name server
        // Domain is saved in the name server and not in the pkarr zone.
        publish_domain().await;
        let mut query = Packet::new_query(0);
        let qname = Name::new("sub.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let raw_reply = resolve_query_recursively(raw_query).await;
        let reply = Packet::parse(&raw_reply).unwrap();
        assert_eq!(reply.answers.len(), 1);
        let a = reply.answers.get(0).unwrap().clone().into_owned();
        assert!(a.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A)));
        assert_eq!(
            a.rdata,
            RData::A(A {
                address: Ipv4Addr::new(37, 27, 13, 182).to_bits()
            })
        );
    }

    #[tokio::test]
    async fn recursion_ns_soa_icann() {
        // NS SOA record with lots of cnames
        let mut query = Packet::new_query(0);
        let qname = Name::new("ap.lijit.com").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let raw_reply = resolve_query_recursively(raw_query).await;
        let final_reply = Packet::parse(&raw_reply).unwrap();
        dbg!(&final_reply);
        assert!(final_reply.answers.len() > 0);
    }

    // TODO: tld support for NS referrals
    // #[tokio::test]
    // async fn recursion_ns_pkd_with_tld() {
    //     // Single recursion with a delegated zone with an external name server
    //     // Domain is saved in the name server and not in the pkarr zone.
    //     publish_domain().await;
    //     let mut query = Packet::new_query(0);
    //     let qname = Name::new("sub.csjbhp9jpbomwh3m5eyrj1py41m8sjpkzzqmzpj5madsi7sc4mto.key").unwrap();
    //     let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
    //     let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
    //     let question = Question::new(qname, qtype, qclass, false);
    //     query.questions = vec![question];
    //     query.set_flags(PacketFlag::RECURSION_DESIRED);
    //     let raw_query = query.build_bytes_vec_compressed().unwrap();

    //     let raw_reply = resolve_query_recursively(raw_query).await;
    //     let reply = Packet::parse(&raw_reply).unwrap();
    //     assert_eq!(reply.answers.len(), 1);
    //     let a = reply.answers.get(0).unwrap().clone().into_owned();
    //     assert!(a.match_qtype(pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A)));
    //     assert_eq!(
    //         a.rdata,
    //         RData::A(A {
    //             address: Ipv4Addr::new(37, 27, 13, 182).to_bits()
    //         })
    //     );
    // }
}
