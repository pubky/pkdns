#![allow(unused)]
use crate::{
    config::get_global_config,
    resolution::{helpers::replace_packet_id, pkd::CustomHandlerError},
};

use super::{
    pending_request::{PendingRequest, PendingRequestStore},
    pkd::{PkarrResolver, ResolverSettings, TopLevelDomain},
    query_id_manager::QueryIdManager,
    rate_limiter::{RateLimiter, RateLimiterBuilder},
    response_cache::IcannLruCache,
};
use simple_dns::{Packet, SimpleDnsError, QTYPE, RCODE};
use std::num;
use std::{
    hash::{Hash, Hasher},
    num::NonZeroU64,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
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
}

impl DnsSocket {
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
        })
    }

    // Send message to address
    pub async fn send_to(&self, buffer: &[u8], target: &SocketAddr) -> tokio::io::Result<usize> {
        self.socket.send_to(buffer, target).await
    }

    /// Starts the receive loop in the background.
    /// Returns the JoinHandle to stop the loop again.
    pub fn start_receive_loop(&self) -> JoinHandle<()> {
        let mut cloned = self.clone();
        let join_handle = tokio::spawn(async move {
            loop {
                if let Err(err) = cloned.receive_datagram().await {
                    tracing::error!("Error while trying to receive. {err}");
                }
            }
        });
        join_handle
    }

    async fn receive_datagram(&mut self) -> Result<(), DnsSocketError> {
        let mut buffer = [0; 1024];
        let (size, from) = self.socket.recv_from(&mut buffer).await?;

        let mut data = buffer.to_vec();
        if data.len() > size {
            data.drain((size + 1)..data.len());
        }
        let packet = Packet::parse(&data)?;
        let packet_id = packet.id();
        let pending = self.pending.remove_by_forward_id(&packet_id, &from);
        if pending.is_some() {
            tracing::trace!("Received response from forward server. Send back to client.");
            let query = pending.unwrap();
            query.tx.send(data).unwrap();
            return Ok(());
        };

        let is_reply = packet.questions.len() == 0;
        if is_reply {
            tracing::debug!(
                "Received reply without an associated query {:?}. forward_id={packet_id} Ignore.",
                packet
            );
            return Ok(());
        };

        // New query
        if self.disable_any_queries {
            let includes_any_type_question = packet
                .questions
                .iter()
                .map(|q| q.qtype == QTYPE::ANY)
                .reduce(|a, b| a || b);
            if let Some(includes_any_type_question) = includes_any_type_question {
                if includes_any_type_question {
                    tracing::debug!("Received ANY type question from {from}. id={packet_id}. Drop.");
                    return Ok(());
                }
            }
        }

        if self.rate_limiter.check_is_limited_and_increase(from.ip()) {
            tracing::trace!("Rate limited {}. query_id={packet_id}", from.ip());
            let reply = Self::create_refused_reply(packet_id);
            self.send_to(&reply, &from).await?;
            return Ok(());
        };

        let mut socket = self.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            let query_packet = Packet::parse(&data).unwrap();

            let question = query_packet.questions.first();
            if question.is_none() {
                tracing::debug!(
                    "Query with no associated a question {:?}. Ignore. query_id={}",
                    query_packet,
                    query_packet.id()
                );
                return;
            };
            let question = question.unwrap();
            let labels = question.qname.get_labels();
            if labels.len() == 0 {
                tracing::debug!(
                    "DNS packet question with no domain. Ignore. query_id={}",
                    query_packet.id()
                );
                return;
            };
            tracing::trace!(
                "Received new query {} {:?}. query_id={}",
                question.qname,
                question.qtype,
                query_packet.id()
            );
            let query_result = socket.on_query(&data, &from).await;
            match query_result {
                Ok(_) => {
                    tracing::debug!(
                        "Processed query {} {:?} within {}ms. query_id={}",
                        question.qname,
                        question.qtype,
                        start.elapsed().as_millis(),
                        query_packet.id()
                    );
                }
                Err(err) => {
                    tracing::error!(
                        "Failed to respond to query {} {:?}: {} query_id={}",
                        question.qname,
                        question.qtype,
                        err,
                        query_packet.id()
                    );
                }
            };
        });

        Ok(())
    }

    // New query received.
    async fn on_query(&mut self, query: &Vec<u8>, from: &SocketAddr) -> Result<usize, std::io::Error> {
        let reply = self.query_me(query, Some(from.ip())).await;
        self.send_to(&reply, from).await
    }

    /// Query this DNS for data
    pub async fn query_me(&mut self, query: &Vec<u8>, from: Option<IpAddr>) -> Vec<u8> {
        let request = Packet::parse(query).expect("Should be valid query. Prevalidated already.");
        let question = request
            .questions
            .first()
            .expect("No question in query in pkarr_resolver.")
            .clone();

        tracing::debug!(
            "New query: {} {:?} id={}",
            question.qname.to_string(),
            question.qtype,
            request.id()
        );

        tracing::trace!("Try to resolve the query with the custom handler.");
        let result = self.pkarr_resolver.resolve(query, from).await;

        if result.is_ok() {
            tracing::trace!("Custom handler resolved the query.");
            // All good. Handler handled the query
            return result.unwrap();
        }

        let question = request
            .questions
            .first()
            .expect("Should be valid query. Prevalidated already.");
        let query_id = request.id();

        let query_name = format!("{} {:?} query_id={query_id}", question.qname, question.qtype);

        match result.unwrap_err() {
            CustomHandlerError::Unhandled => {
                // Fallback to ICANN
                tracing::trace!("Custom handler rejected the query. {query_name}");
                match self.forward_to_icann(query, Duration::from_secs(5)).await {
                    Ok(reply) => reply,
                    Err(e) => {
                        tracing::warn!("Forwarding dns query failed. {e} {query_name}");
                        Self::create_server_fail_reply(query_id)
                    }
                }
            }
            CustomHandlerError::Failed(err) => {
                tracing::error!("Internal error {query_name}: {}", err);
                Self::create_server_fail_reply(query_id)
            }
            CustomHandlerError::RateLimited(ip) => {
                tracing::error!("IP is rate limited {query_name}: {}", ip);
                Self::create_refused_reply(query_id)
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
    pub async fn forward_to_icann(&mut self, query: &Vec<u8>, timeout: Duration) -> Result<Vec<u8>, DnsSocketError> {
        // Check cache first before forwarding
        if let Ok(opt_item) = self.icann_cache.get(query).await {
            if let Some(item) = opt_item {
                let query_packet = Packet::parse(query)?;
                let new_response = replace_packet_id(&item.response, query_packet.id())?;
                return Ok(new_response);
            };
        };

        let reply = self.forward(query, &self.icann_fallback.clone(), timeout).await?;
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
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::resolution::pkd::PkarrResolver;
    use simple_dns::{Name, Packet, PacketFlag, Question, RCODE};
    use std::{net::SocketAddr, time::Duration};

    use super::DnsSocket;

    #[tokio::test]
    async fn run_processor() {
        let listening: SocketAddr = "0.0.0.0:34254".parse().unwrap();
        let icann_fallback: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut socket = DnsSocket::default().await.unwrap();
        let join_handle = socket.start_receive_loop().await;

        let mut query = Packet::new_query(0);
        let qname = Name::new("google.ch").unwrap();
        let qtype = simple_dns::QTYPE::TYPE(simple_dns::TYPE::A);
        let qclass = simple_dns::QCLASS::CLASS(simple_dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];

        let query = query.build_bytes_vec_compressed().unwrap();
        let to: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = socket.forward(&query, &to, Duration::from_secs(5)).await.unwrap();
        let reply = Packet::parse(&result).unwrap();
        dbg!(reply);
    }
}
