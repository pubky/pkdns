use pkarr::dns::{Packet, SimpleDnsError};

/// Replaces the id of a dns packet.
pub fn replace_packet_id(packet: &Vec<u8>, new_id: u16) -> Result<Vec<u8>, SimpleDnsError> {
    let mut cloned = packet.clone();
    let id_bytes = new_id.to_be_bytes();
    std::mem::replace(&mut cloned[0], id_bytes[0]);
    std::mem::replace(&mut cloned[1], id_bytes[1]);

    let parsed_packet = Packet::parse(&cloned)?;
    Ok(parsed_packet.build_bytes_vec()?)
}
