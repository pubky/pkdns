#![allow(unused)]
use super::{
    custom_handler::{CustomHandlerError, HandlerHolder},
    pending_request::{PendingRequest, PendingRequestStore},
    query_id_manager::QueryIdManager,
    rate_limiter::RateLimiter,
};
use simple_dns::{Packet, SimpleDnsError, RCODE};
use std::hash::{Hash, Hasher};
use std::num;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::oneshot};
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
}

/**
 * DNS UDP socket
 */
#[derive(Debug, Clone)]
pub struct DnsSocket {
    socket: Arc<UdpSocket>,
    pending: PendingRequestStore,
    handler: HandlerHolder,
    icann_fallback: SocketAddr,
    id_manager: QueryIdManager,
    rate_limiter: Arc<RateLimiter>,
}

impl DnsSocket {
    // Create a new DNS socket
    pub async fn new(
        listening: SocketAddr,
        icann_fallback: SocketAddr,
        handler: HandlerHolder,
        max_queries_per_ip_per_second: Option<NonZeroU32>,
    ) -> tokio::io::Result<Self> {
        let socket = UdpSocket::bind(listening).await?;

        Ok(Self {
            socket: Arc::new(socket),
            pending: PendingRequestStore::new(),
            handler,
            icann_fallback,
            id_manager: QueryIdManager::new(),
            rate_limiter: Arc::new(RateLimiter::new_per_second(max_queries_per_ip_per_second)),
        })
    }

    // Send message to address
    pub async fn send_to(&self, buffer: &[u8], target: &SocketAddr) -> tokio::io::Result<usize> {
        self.socket.send_to(buffer, target).await
    }

    // Run receive loop
    pub async fn receive_loop(&mut self) {
        loop {
            if let Err(err) = self.receive_datagram().await {
                tracing::error!("Error while trying to receive. {err}");
            }
        }
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
            tracing::debug!("Received reply without an associated query {:?}. forward_id={packet_id} Ignore.", packet);
            return Ok(());
        };

        // New query
        if self.rate_limiter.check_is_limited_and_increase(from.ip()) {
            tracing::trace!("Rate limited {}. query_id={packet_id}", from.ip());
            let reply = self.create_refused_reply(packet_id);
            self.send_to(&reply, &from).await?;
            return Ok(());
        };

        let mut socket = self.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            let query_packet = Packet::parse(&data).unwrap();

            let question = query_packet.questions.first();
            if question.is_none() {
                tracing::debug!("Query with no associated a question {:?}. Ignore. query_id={}", query_packet, query_packet.id());
                return;
            };
            let question = question.unwrap();
            let labels = question.qname.get_labels();
            if labels.len() == 0 {
                tracing::debug!("DNS packet question with no domain. Ignore. query_id={}", query_packet.id());
                return;
            };
            tracing::trace!("Received new query {} {:?}. query_id={}", question.qname, question.qtype, query_packet.id());
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
        tracing::trace!("Try to resolve the query with the custom handler.");
        let result = self.handler.call(query, self.clone(), from).await;

        if result.is_ok() {
            tracing::trace!("Custom handler resolved the query.");
            // All good. Handler handled the query
            return result.unwrap();
        }
        let query_id = self.extract_query_id(query).expect("Should be valid query. Prevalidated already.");

        match result.unwrap_err() {
            CustomHandlerError::Unhandled => {
                // Fallback to ICANN
                tracing::trace!("Custom handler rejected the query.");
                match self.forward_to_icann(query, Duration::from_secs(5)).await {
                    Ok(reply) => reply,
                    Err(e) => {
                        tracing::warn!("Forward dns server error. {e}. query_id={query_id}");
                        self.create_server_fail_reply(query_id)
                    },
                }
            }
            CustomHandlerError::Failed(err) => {
                tracing::error!("Internal error: {}", err);
                self.create_server_fail_reply(query_id)
            },
            CustomHandlerError::RateLimited(ip) => {
                tracing::error!("IP is rate limited: {}", ip);
                self.create_refused_reply(query_id)
            },
        }

    }

    /// Replaces the id of the dns packet.
    fn replace_packet_id(&self, packet: &mut Vec<u8>, new_id: u16) {
        let id_bytes = new_id.to_be_bytes();
        std::mem::replace(&mut packet[0], id_bytes[0]);
        std::mem::replace(&mut packet[1], id_bytes[1]);
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

        let mut query = packet.build_bytes_vec_compressed()?;
        self.replace_packet_id(&mut query, forward_id);

        self.pending.insert(request);
        self.send_to(&query, to).await?;

        // Wait on response
        let reply = tokio::time::timeout(timeout, rx).await;
        if reply.is_err() {
            // Timeout, remove pending again
            tracing::info!("Forwarded query original_id={original_id} forward_id={forward_id} timed out.");
            self.pending.remove_by_forward_id(&forward_id, &to);
        };
        let mut reply = reply?.unwrap();
        self.replace_packet_id(&mut reply, original_id);
        Ok(reply)
    }

    /// Forward query to icann
    pub async fn forward_to_icann(&mut self, query: &Vec<u8>, timeout: Duration) -> Result<Vec<u8>, DnsSocketError> {
        self.forward(query, &self.icann_fallback.clone(), timeout).await
    }

    // Extracts the id of the query
    fn extract_query_id(&self, query: &Vec<u8>) -> Result<u16, SimpleDnsError> {
         Packet::parse(query).map(|packet| packet.id())
    }

    /// Create a REFUSED reply
    fn create_refused_reply(&self, query_id: u16) -> Vec<u8> {
        let mut reply = Packet::new_reply(query_id);
        *reply.rcode_mut() = RCODE::Refused;
        reply.build_bytes_vec_compressed().unwrap()
    }

    /// Create SRVFAIL reply
    fn create_server_fail_reply(&self, query_id: u16) -> Vec<u8> {
        let mut reply = Packet::new_reply(query_id);
        *reply.rcode_mut() = RCODE::ServerFailure;
        reply.build_bytes_vec_compressed().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use simple_dns::{Name, Packet, PacketFlag, Question, RCODE};
    use std::{net::SocketAddr, time::Duration};

    use super::super::custom_handler::{EmptyHandler, HandlerHolder};

    use super::DnsSocket;

    #[tokio::test]
    async fn run_processor() {
        let listening: SocketAddr = "0.0.0.0:34254".parse().unwrap();
        let icann_fallback: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let handler = HandlerHolder::new(EmptyHandler::new());
        let mut socket = DnsSocket::new(listening, icann_fallback, handler, None).await.unwrap();

        let mut run_socket = socket.clone();
        tokio::spawn(async move {
            run_socket.receive_loop().await;
        });

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
