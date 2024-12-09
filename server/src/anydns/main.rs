mod custom_handler;
mod dns_socket;
mod pending_request;
mod query_id_manager;
mod server;

use std::{error::Error, net::Ipv4Addr};

use any_dns::{Builder, CustomHandler, CustomHandlerError, DnsSocket};
use async_trait::async_trait;
use simple_dns::{Packet, ResourceRecord, QTYPE, TYPE};

#[derive(Clone, Debug)]
struct MyHandler {}

#[async_trait]
impl CustomHandler for MyHandler {
    /**
     * Only resolve 1 custom domain any.dns.
     */
    async fn lookup(
        &mut self,
        query: &Vec<u8>,
        _socket: DnsSocket,
    ) -> Result<Vec<u8>, CustomHandlerError> {
        // Parse query with any dns library. Here, we use `simple_dns``.
        let packet = Packet::parse(query).unwrap();
        let question = packet.questions.get(0).expect("Valid query");

        let is_any_dot_dns =
            question.qname.to_string() == "any.dns" && question.qtype == QTYPE::TYPE(TYPE::A);
        if is_any_dot_dns {
            Ok(self.construct_reply(query)) // Reply with A record IP
        } else {
            Err(CustomHandlerError::Unhandled) // Fallback to ICANN
        }
    }
}

impl MyHandler {
    // Construct reply packet
    fn construct_reply(&self, query: &Vec<u8>) -> Vec<u8> {
        let packet = Packet::parse(query).unwrap();
        let question = packet.questions.get(0).expect("Valid query");
        let mut reply = Packet::new_reply(packet.id());
        reply.questions.push(question.clone());
        let ip: Ipv4Addr = "37.27.13.182".parse().unwrap();
        let record = ResourceRecord::new(
            question.qname.clone(),
            simple_dns::CLASS::IN,
            120,
            simple_dns::rdata::RData::A(ip.try_into().unwrap()),
        );
        reply.answers.push(record);
        reply.build_bytes_vec().unwrap()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Listening on 0.0.0.0:53. Waiting for Ctrl-C...");
    let handler = MyHandler {};
    let anydns = Builder::new()
        .handler(handler)
        .icann_resolver("8.8.8.8:53".parse().unwrap())
        .build()
        .await?;

    anydns.wait_on_ctrl_c().await;
    tracing::info!("Got it! Exiting...");
    anydns.stop();

    Ok(())
}
