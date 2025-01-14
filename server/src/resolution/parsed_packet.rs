use anyhow::anyhow;
use chrono::format::Parsed;
use pkarr::dns::Packet;
use self_cell::self_cell;
use std::{fmt::Display, pin::Pin};

self_cell!(
    struct Inner {
        owner: Vec<u8>,

        #[covariant]
        dependent: Packet,
    }

    impl {Debug}
);

impl Inner {
    /// Try to parse the packet from bytes
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, pkarr::dns::SimpleDnsError> {
        Self::try_new(bytes, |bytes| Packet::parse(&bytes))
    }

    /// Parsed DNS packet
    pub fn packet(&self) -> &Packet {
        self.borrow_dependent()
    }

    /// Raw bytes the packet is build with
    pub fn raw_bytes(&self) -> &Vec<u8> {
        &self.borrow_owner()
    }
}

impl Clone for Inner {
    fn clone(&self) -> Self {
        let bytes = self.raw_bytes().clone();
        Self::try_from_bytes(bytes).unwrap()
    }
}


#[derive(Debug, Clone)]
pub struct ParsedPacket {
    inner: Inner,
}

impl ParsedPacket {
    pub fn new(raw_bytes: Vec<u8>) -> Result<Self, pkarr::dns::SimpleDnsError> {
        let inner = Inner::try_from_bytes(raw_bytes)?;
        Ok(Self { inner })
    }

    /// Parsed DNS packet
    pub fn packet(&self) -> &Packet {
        self.inner.packet()
    }

    /// Raw bytes the packet is build with
    pub fn raw_bytes(&self) -> &Vec<u8> {
        &self.inner.raw_bytes()
    }

    /// Checks if this packet is valid.
    pub fn is_valid(&self) -> Result<(), anyhow::Error> {
        let packet = self.packet();
        let question = packet.questions.first();
        if question.is_none() {
            return Err(anyhow!("Packet without a question."));
        };
        let question = question.unwrap();
        let labels = question.qname.get_labels();
        if labels.len() == 0 {
            return Err(anyhow!("Question with an empty qname."));
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pkarr::dns::{Name, Packet, PacketFlag, Question};

    use super::*;
    #[tokio::test]
    async fn try_from_bytes() {
        let mut query = Packet::new_query(0);
        let qname = Name::new("example.com").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let parsed = ParsedPacket::new(raw_query).unwrap();
        assert_eq!(parsed.packet().id(), 0);
    }
}
