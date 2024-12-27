#![allow(unused)]

/**
 * Basic module to process DNS queries with a UDP socket.
 * Allows to hook into the socket and process custom queries.
 */
mod dns_socket;
mod dns_socket_builder;
mod pending_request;
mod query_id_manager;
mod rate_limiter;
mod pkd;

pub use dns_socket::{DnsSocket, DnsSocketError};
pub use dns_socket_builder::DnsSocketBuilder;
pub use rate_limiter::{RateLimiter, RateLimiterBuilder};