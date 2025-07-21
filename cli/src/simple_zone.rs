use anyhow::anyhow;
use domain::{
    base::Rtype,
    zonefile::inplace::{Entry, Zonefile},
};
use pkarr::dns::{Name, Packet, ResourceRecord};
use std::io::Cursor;

use crate::pkarr_packet::PkarrPacket;

/**
 * Reads a dns zone file without the otherwise necessary SOA entry.
 */
#[derive(Debug)]
pub struct SimpleZone {
    pub packet: PkarrPacket,
}

impl SimpleZone {
    /**
     * Read the zone data. Pkarr pubkey must be provided in zbase32 format.
     */
    pub fn read(simplified_zone: String, pubkey: &str) -> Result<Self, anyhow::Error> {
        let entries = Self::parse_simplified_zone(simplified_zone, pubkey)?;
        let packet = Self::entries_to_simple_dns_packet(entries)?;
        Ok(Self {
            packet: PkarrPacket { data: packet },
        })
    }

    /**
     * Generate a fake soa entry to simplify the
     * zone file the user needs to write.
     */
    fn generate_soa(pubkey: &str) -> String {
        let formatted = format!(
            "$ORIGIN {pubkey}. 
$TTL 300
@	IN	SOA	127.0.0.1.	hostmaster.example.com. (
			2001062501 ; serial                     
			21600      ; refresh after 6 hours                     
			3600       ; retry after 1 hour                     
			604800     ; expire after 1 week                     
			300 )    ; minimum TTL of 1 day  
            "
        );
        formatted
    }

    /**
     * Parses the zone data. Returns domain::Entry list.
     */
    fn parse_simplified_zone(simplified_zone: String, pubkey: &str) -> Result<Vec<Entry>, anyhow::Error> {
        let raw_soa = SimpleZone::generate_soa(pubkey);
        let zone = format!("{raw_soa}\n{simplified_zone}\n");

        let byte_data = zone.into_bytes();
        let mut cursor = Cursor::new(byte_data);
        let zone = Zonefile::load(&mut cursor)?;

        let mut entries: Vec<Entry> = vec![];
        for entry_res in zone.into_iter() {
            let entry = entry_res?;

            let should_include: bool = match entry.clone() {
                Entry::Record(val) => val.rtype() != Rtype::SOA,
                _ => false,
            };
            if should_include {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /**
     * Converts domain::Entry to simple-dns packet bytes.
     */
    fn entries_to_simple_dns_packet(entries: Vec<Entry>) -> Result<Vec<u8>, anyhow::Error> {
        let mut packets = vec![];
        for entry in entries.iter() {
            let entry = entry.clone();
            let packet = match entry {
                Entry::Include { .. } => continue,
                Entry::Record(val) => {
                    let ttl = val.ttl().as_secs();
                    let (name, data) = val.clone().into_owner_and_data();
                    let simple_name_str = name.to_string();
                    let simple_name = Name::try_from(simple_name_str.as_str())?;
                    let simple_data = match data {
                        domain::rdata::ZoneRecordData::A(val) => {
                            let rdata: pkarr::dns::rdata::RData = pkarr::dns::rdata::RData::A(pkarr::dns::rdata::A {
                                address: val.addr().into(),
                            });
                            let rr = ResourceRecord::new(simple_name, pkarr::dns::CLASS::IN, ttl, rdata);
                            let mut packet = pkarr::dns::Packet::new_reply(0);
                            packet.answers.push(rr);
                            packet.build_bytes_vec_compressed()?
                        }
                        domain::rdata::ZoneRecordData::Aaaa(val) => {
                            let rdata: pkarr::dns::rdata::RData =
                                pkarr::dns::rdata::RData::AAAA(pkarr::dns::rdata::AAAA {
                                    address: val.addr().into(),
                                });
                            let rr = ResourceRecord::new(simple_name, pkarr::dns::CLASS::IN, ttl, rdata);
                            let mut packet = pkarr::dns::Packet::new_reply(0);
                            packet.answers.push(rr);
                            packet.build_bytes_vec_compressed()?
                        }
                        domain::rdata::ZoneRecordData::Ns(val) => {
                            let ns_name = val.to_string();
                            let rdata: pkarr::dns::rdata::RData =
                                pkarr::dns::rdata::RData::NS(pkarr::dns::rdata::NS(Name::try_from(ns_name.as_str())?));

                            let rr = ResourceRecord::new(simple_name, pkarr::dns::CLASS::IN, ttl, rdata);
                            let mut packet = pkarr::dns::Packet::new_reply(0);
                            packet.answers.push(rr);
                            packet.build_bytes_vec_compressed()?
                        }

                        domain::rdata::ZoneRecordData::Txt(val) => {
                            let mut txt = pkarr::dns::rdata::TXT::new();

                            for bytes in val.iter() {
                                let ascii = std::str::from_utf8(bytes).unwrap();
                                txt.add_string(ascii)?;
                            }
                            let rdata: pkarr::dns::rdata::RData = pkarr::dns::rdata::RData::TXT(txt);

                            let rr = ResourceRecord::new(simple_name, pkarr::dns::CLASS::IN, ttl, rdata);
                            let mut packet = pkarr::dns::Packet::new_reply(0);
                            packet.answers.push(rr);
                            packet.build_bytes_vec_compressed()?
                        }
                        domain::rdata::ZoneRecordData::Mx(val) => {
                            let exchange = val.exchange().to_string();
                            let mx = pkarr::dns::rdata::MX {
                                preference: val.preference(),
                                exchange: Name::try_from(exchange.as_str())?,
                            };

                            let rdata: pkarr::dns::rdata::RData = pkarr::dns::rdata::RData::MX(mx);

                            let rr = ResourceRecord::new(simple_name, pkarr::dns::CLASS::IN, ttl, rdata);
                            let mut packet = pkarr::dns::Packet::new_reply(0);
                            packet.answers.push(rr);
                            packet.build_bytes_vec_compressed()?
                        }
                        domain::rdata::ZoneRecordData::Cname(val) => {
                            let value = val.to_string();
                            let value = Name::try_from(value.as_str()).unwrap();
                            let rdata: pkarr::dns::rdata::RData =
                                pkarr::dns::rdata::RData::CNAME(pkarr::dns::rdata::CNAME(value));
                            let rr = ResourceRecord::new(simple_name, pkarr::dns::CLASS::IN, ttl, rdata);
                            let mut packet = pkarr::dns::Packet::new_reply(0);
                            packet.answers.push(rr);
                            packet.build_bytes_vec_compressed()?
                        }
                        _ => return Err(anyhow!("Not support record type.")),
                    };
                    simple_data
                }
            };
            packets.push(packet);
        }
        let mut final_packet = Packet::new_reply(0);
        for packet in packets.iter() {
            let parsed = Packet::parse(packet)?;
            for answer in parsed.answers {
                final_packet.answers.push(answer)
            }
        }
        Ok(final_packet.build_bytes_vec_compressed()?)
    }
}

#[cfg(test)]
mod tests {

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    fn simplified_zone() -> String {
        String::from(
            "
@	IN	NS	dns1.example.com. 
@ 400	IN	NS	dns2.example.com.        
	
	
@ 301	IN	MX	10	mail.example.com.       
@	IN	MX	20	mail2.example.com.   

@   IN  A 127.0.0.1
test   IN  A 127.0.0.1

	
dns1	IN	A	10.0.1.1
dns2	IN	A	10.0.1.2

text    IN  TXT  hero=satoshi 
",
        )
    }

    #[test]
    fn test_create_entries() {
        let simplified_zone = simplified_zone();
        let zone = SimpleZone::read(simplified_zone, "123456");
        let zone = zone.unwrap();
        assert_eq!(zone.packet.parsed().answers.len(), 9);

        println!("{}", zone.packet);
    }

    #[test]
    fn test_transform() {
        let simplified_zone = simplified_zone();
        let zone = SimpleZone::read(simplified_zone, "123456").unwrap();
        let packet = zone.packet.parsed();

        println!("{:#?}", packet.answers);
    }

    #[test]
    fn test_pkarr_records() {
        let records = "
@				IN 		A		37.27.13.182
pknames.p2p		IN 		A		37.27.13.182
www.pknames.p2p	IN		CNAME	pknames.p2p.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.
sub				IN		NS		ns.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.
ns				IN		A		95.217.214.181
cname			IN		CNAME	example.com.
_text			IN		TXT		hero=satoshi";

        let zone = SimpleZone::read(records.to_string(), "123456").unwrap();
        let packet = zone.packet.parsed();

        println!("{:#?}", packet.answers);
    }

    #[test]
    fn test_read_zone_txt1() {
        let raw_records = "foo   IN  TXT   \"key1=1\" \"key2=2\"";

        let zone = SimpleZone::read(raw_records.to_string(), "123456").unwrap();
        let packet = zone.packet.parsed();

        let entry = packet.answers.first().unwrap();

        match &entry.rdata {
            pkarr::dns::rdata::RData::TXT(txt) => {
                let value1 = txt.clone().attributes().get("key1").unwrap().clone().unwrap();
                assert_eq!(value1, "1");
                let value2 = txt.clone().attributes().get("key2").unwrap().clone().unwrap();
                assert_eq!(value2, "2");
            }
            _ => panic!("Expected TXT record, got {:?}", entry.rdata),
        }
    }

    #[test]
    fn test_read_zone_txt2() {
        let raw_records = "foo   IN  TXT   key=value";

        let zone = SimpleZone::read(raw_records.to_string(), "123456").unwrap();
        let packet = zone.packet.parsed();
        let entry = packet.answers.last().unwrap();

        match &entry.rdata {
            pkarr::dns::rdata::RData::TXT(txt) => {
                let value = txt.clone().attributes().get("key").unwrap().clone().unwrap();
                assert_eq!(value, "value");
            }
            _ => panic!("Expected TXT record, got {:?}", entry.rdata),
        }
    }

    #[test]
    fn test_read_zone_txt3() {
        let raw_records = "foo   IN  TXT   \"key=value\"";

        let zone = SimpleZone::read(raw_records.to_string(), "123456").unwrap();
        let packet = zone.packet.parsed();
        let entry = packet.answers.last().unwrap();

        match &entry.rdata {
            pkarr::dns::rdata::RData::TXT(txt) => {
                let value = txt.clone().attributes().get("key").unwrap().clone().unwrap();
                assert_eq!(value, "value");
            }
            _ => panic!("Expected TXT record, got {:?}", entry.rdata),
        }
    }
}
