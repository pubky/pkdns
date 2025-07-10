use anyhow::anyhow;
use chrono::format::Parsed;
use pkarr::dns::{Packet, PacketFlag};
use self_cell::self_cell;
use std::{fmt::Display, pin::Pin};

// Struct to hold the bytes and the packet in one place
// to avoid lifetimes aka a self-referencing struct.
self_cell!(
    pub struct Inner {
        owner: Vec<u8>,

        #[covariant]
        dependent: Packet,
    }

    impl {Debug}
);

impl Inner {
    /// Try to parse the packet from bytes
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, pkarr::dns::SimpleDnsError> {
        Self::try_new(bytes, |bytes| Packet::parse(bytes))
    }

    /// Parsed DNS packet
    pub fn packet(&self) -> &Packet {
        self.borrow_dependent()
    }

    /// Raw bytes the packet is build with
    pub fn raw_bytes(&self) -> &Vec<u8> {
        self.borrow_owner()
    }
}

impl Clone for Inner {
    fn clone(&self) -> Self {
        let bytes = self.raw_bytes().clone();
        Self::try_from_bytes(bytes).unwrap()
    }
}

impl From<Inner> for Vec<u8> {
    fn from(val: Inner) -> Self {
        val.into_owner()
    }
}

/// Parses a dns packet without having to deal with life times
/// Both the raw bytes and the parsed struct is contained.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub inner: Inner,
}

impl ParsedPacket {
    pub fn new(raw_bytes: Vec<u8>) -> Result<Self, pkarr::dns::SimpleDnsError> {
        let inner = Inner::try_from_bytes(raw_bytes)?;
        Ok(Self { inner })
    }

    pub fn id(&self) -> u16 {
        self.parsed().id()
    }

    /// Parsed DNS packet
    pub fn parsed(&self) -> &Packet {
        self.inner.packet()
    }

    /// Raw bytes the packet is build with
    pub fn raw_bytes(&self) -> &Vec<u8> {
        self.inner.raw_bytes()
    }

    /// If this packet is a reply
    pub fn is_reply(&self) -> bool {
        self.parsed().has_flags(PacketFlag::RESPONSE)
    }

    /// If this packet is a reply
    pub fn is_query(&self) -> bool {
        !self.parsed().has_flags(PacketFlag::RESPONSE)
    }

    /// Create a REFUSED reply
    pub fn create_refused_reply(&self) -> Vec<u8> {
        let mut reply = Packet::new_reply(self.id());
        *reply.rcode_mut() = pkarr::dns::RCODE::Refused;
        reply.build_bytes_vec_compressed().unwrap()
    }

    /// Create SRVFAIL reply
    pub fn create_server_fail_reply(&self) -> Vec<u8> {
        let mut reply = Packet::new_reply(self.id());
        *reply.rcode_mut() = pkarr::dns::RCODE::ServerFailure;
        reply.build_bytes_vec_compressed().unwrap()
    }
}

impl From<ParsedPacket> for Vec<u8> {
    fn from(val: ParsedPacket) -> Self {
        val.inner.into()
    }
}

#[cfg(test)]
mod tests {
    use pkarr::dns::{Name, Packet, PacketFlag, Question};

    use super::*;
    #[tokio::test]
    async fn new() {
        let mut query = Packet::new_query(0);
        let qname = Name::new("example.com").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let parsed = ParsedPacket::new(raw_query).unwrap();
        assert_eq!(parsed.parsed().id(), 0);
    }
}
