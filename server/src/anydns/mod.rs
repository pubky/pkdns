#![allow(unused)]

/**
 * Basic module to process DNS queries with a UDP socket.
 * Allows to hook into the socket and process custom queries.
 */

mod custom_handler;
mod dns_socket;
mod pending_request;
mod query_id_manager;
mod server;

pub use custom_handler::{CustomHandler, CustomHandlerError, EmptyHandler, HandlerHolder};
pub use dns_socket::DnsSocket;
pub use server::{AnyDNS, Builder};
