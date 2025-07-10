use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::anyhow;
use pkarr::dns::{rdata::RData, Name, Packet, ResourceRecord};

/**
 * Full pkarr dns packet. All data is saved in the answers.
 */
#[derive(Debug)]
pub struct PkarrPacket {
    pub data: Vec<u8>,
}

impl PkarrPacket {
    pub fn empty() -> Self {
        let packet = Packet::new_reply(0);
        let data = packet.build_bytes_vec_compressed().unwrap();
        Self { data }
    }

    pub fn by_data(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn parsed(&self) -> Packet {
        Packet::parse(&self.data).unwrap()
    }

    pub fn to_records(&self) -> Vec<PkarrRecord> {
        self.parsed()
            .answers
            .iter()
            .map(|answer| PkarrRecord::by_resource_record(answer))
            .collect()
    }

    pub fn answers_len(&self) -> usize {
        self.parsed().answers.len()
    }

    pub fn is_emtpy(&self) -> bool {
        self.answers_len() == 0
    }
}

impl fmt::Display for PkarrPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.answers_len() == 0 {
            writeln!(f, "Packet is empty.")?;
            return Ok(());
        };
        let records = self.to_records();
        writeln!(f, "Packet {}", records.first().unwrap().pubkey())?;
        writeln!(f, "Name TTL Type Data")?;
        for record in self.to_records() {
            writeln!(f, "{record}")?;
        }
        Ok(())
    }
}

/**
 * Simple Pkarr record
 */
pub struct PkarrRecord {
    pub data: Vec<u8>,
}

impl PkarrRecord {
    #[allow(dead_code)]
    pub fn by_data(data: Vec<u8>) -> Result<Self, anyhow::Error> {
        let result = Packet::parse(&data);
        if let Err(e) = result {
            return Err(e.into());
        }
        let packet = result.unwrap();
        if packet.answers.len() != 1 {
            return Err(anyhow!("packet data must contain 1 answer."));
        }

        Ok(Self { data })
    }

    pub fn by_resource_record(rr: &ResourceRecord) -> Self {
        let rr = rr.clone();
        let mut packet = Packet::new_reply(0);
        packet.answers.push(rr);
        Self {
            data: packet.build_bytes_vec_compressed().unwrap(),
        }
    }

    pub fn get_resource_record(&self) -> ResourceRecord {
        let packet = Packet::parse(&self.data).unwrap();
        packet.answers[0].clone()
    }

    pub fn pubkey(&self) -> String {
        let rr = self.get_resource_record();
        let pubkey = rr.name.get_labels().last().unwrap();
        pubkey.to_string()
    }

    pub fn name(&self) -> String {
        let pubkey = self.pubkey();

        let name = Name::try_from(pubkey.as_str()).unwrap();
        let rr = self.get_resource_record();
        let name = rr.name.without(&name);
        match name {
            Some(n) => n.to_string(),
            None => "@".to_string(),
        }
    }

    pub fn ttl(&self) -> u32 {
        let rr = self.get_resource_record();
        rr.ttl
    }

    pub fn data_as_strings(&self) -> (&str, String) {
        let (record_type, data) = match self.get_resource_record().rdata {
            RData::A(a) => {
                let ipv4 = Ipv4Addr::from(a.address);
                ("A", ipv4.to_string())
            }
            RData::AAAA(val) => {
                let ipv6 = Ipv6Addr::from(val.address);
                ("AAAA", ipv6.to_string())
            }
            RData::CNAME(val) => {
                let data = val.to_string();
                ("CNAME", data)
            }
            RData::MX(val) => {
                let data = format!("{} - {}", val.preference, val.exchange);
                ("MX", data)
            }
            RData::TXT(val) => {
                let data = val
                    .attributes()
                    .iter()
                    .map(|(key, val)| {
                        if val.is_some() {
                            format!("{}={}", key, val.clone().unwrap())
                        } else {
                            format!("{}=", key)
                        }
                    })
                    .collect::<Vec<String>>()
                    .join(", ");
                ("TXT", data)
            }
            RData::NS(val) => {
                let data = val.to_string();
                ("NS", data)
            }
            _ => ("Unknown", "Unknown".to_string()),
        };
        (record_type, data)
    }
}

impl fmt::Display for PkarrRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.name();
        let ttl = self.ttl();
        let data = self.data_as_strings();
        write!(f, "{0: <20} {1: <7} {2: <6} {3: <25}", name, ttl, data.0, data.1)
    }
}
