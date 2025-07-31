#![allow(unused)]

/**
 * Basic module to process DNS queries with a UDP socket.
 * Allows to hook into the socket and process custom queries.
 */
mod dns_socket;
// mod dns_socket_builder;
mod helpers;
mod pending_request;
mod pkd;
mod query_id_manager;
mod rate_limiter;
mod response_cache;

mod dns_packets;

pub use dns_socket::{DnsSocket, DnsSocketError};
// pub use dns_socket_builder::DnsSocketBuilder;
pub use rate_limiter::{RateLimiter, RateLimiterBuilder};
