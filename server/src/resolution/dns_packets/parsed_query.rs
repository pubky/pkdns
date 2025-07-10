use std::fmt::Display;

use super::ParsedPacket;
use anyhow::anyhow;
use pkarr::dns::{Packet, PacketFlag, Question, QTYPE};

#[derive(thiserror::Error, Debug)]
pub enum ParseQueryError {
    #[error("Dns packet parse error: {0}")]
    Parse(#[from] pkarr::dns::SimpleDnsError),

    #[error("Query validation error: {0}.")]
    Validation(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub packet: ParsedPacket,
}

impl ParsedQuery {
    /// Create a new parsed query.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ParseQueryError> {
        let packet = ParsedPacket::new(bytes)?;
        let me = Self { packet };
        me.validate()?;
        Ok(me)
    }

    /// Checks if this packet is valid.
    fn validate(&self) -> Result<(), anyhow::Error> {
        if !self.packet.is_query() {
            return Err(anyhow!("Packet is not a query."));
        }
        let question = self.packet.parsed().questions.first();
        if question.is_none() {
            return Err(anyhow!("Packet without a question."));
        };
        let question = question.unwrap();
        let labels = question.qname.get_labels();
        if labels.is_empty() {
            return Err(anyhow!("Question with an empty qname."));
        };

        Ok(())
    }

    pub fn question(&self) -> &Question {
        self.packet.parsed().questions.first().unwrap()
    }

    /// If this query is ANY type which is often used for DNS amplification attacks.
    pub fn is_any_type(&self) -> bool {
        self.question().qtype == QTYPE::ANY
    }

    pub fn is_recursion_desired(&self) -> bool {
        self.packet.parsed().has_flags(PacketFlag::RECURSION_DESIRED)
    }
}

impl Display for ParsedQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let question = self.question();
        let query_id = self.packet.parsed().id();
        let query_name = format!("{} {:?} query_id={query_id}", question.qname, question.qtype);
        write!(
            f,
            "{} {:?} {:?} id={query_id} rd={}",
            question.qname,
            question.qtype,
            question.qclass,
            self.packet.parsed().has_flags(PacketFlag::RECURSION_DESIRED)
        )
    }
}

impl TryFrom<ParsedPacket> for ParsedQuery {
    type Error = ParseQueryError;
    fn try_from(value: ParsedPacket) -> Result<Self, Self::Error> {
        let me = Self { packet: value };
        me.validate()?;
        Ok(me)
    }
}

impl From<ParsedQuery> for ParsedPacket {
    fn from(val: ParsedQuery) -> Self {
        val.packet
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

        let parsed = ParsedQuery::new(raw_query).unwrap();
    }

    #[tokio::test]
    async fn tryfrom_parsed_packet() {
        let mut query = Packet::new_query(0);
        let qname = Name::new("example.com").unwrap();
        let qtype = pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A);
        let qclass = pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        let raw_query = query.build_bytes_vec_compressed().unwrap();

        let parsed = ParsedPacket::new(raw_query).unwrap();
        let parsed_query: ParsedQuery = parsed.try_into().unwrap();
    }
}
