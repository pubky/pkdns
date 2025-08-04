use std::io::Write;
use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use anyhow::anyhow;

use clap::ArgMatches;
use pkarr::{Keypair, SignedPacket, Timestamp};

use crate::external_ip::{resolve_ipv4, resolve_ipv6};
use crate::helpers::nts_to_chrono;
use crate::{helpers::construct_pkarr_client, simple_zone::SimpleZone};

const SECRET_KEY_LENGTH: usize = 32;

/// Replaces {externl_ipv4} and {external_ipv6} variables in the zone file
/// with the according ips.
/// Errors if ips can't be resolved.
async fn fill_dyndns_variables(zone: &mut String) -> Result<(), anyhow::Error> {
    if zone.contains("{external_ipv4}") {
        let ip_result = resolve_ipv4().await;
        if let Err(e) = ip_result {
            return Err(anyhow!(e));
        }
        let (external_ipv4, _) = ip_result.unwrap();
        *zone = zone.replace("{external_ipv4}", &external_ipv4.to_string());
    };

    if zone.contains("{external_ipv6}") {
        let ip_result = resolve_ipv6().await;
        if let Err(e) = ip_result {
            return Err(anyhow!(e));
        }
        let (external_ipv6, _) = ip_result.unwrap();
        *zone = zone.replace("{external_ipv6}", &external_ipv6.to_string());
    };

    Ok(())
}

async fn read_zone_file(zone_file_path: &str, pubkey: &str) -> SimpleZone {
    let csv_path_str: String = shellexpand::full(zone_file_path).expect("Valid shell path.").into();
    let path = Path::new(&csv_path_str);
    let path = PathBuf::from(path);

    let zone = read_to_string(path);
    if let Err(e) = zone {
        eprintln!("Failed to read zone at {csv_path_str}. {e}");
        std::process::exit(1);
    };
    let mut zone = zone.unwrap();
    if let Err(e) = fill_dyndns_variables(&mut zone).await {
        panic!("Failed to fetch external ips. {e}");
    };

    let zone = SimpleZone::read(zone, pubkey);
    if let Err(e) = zone {
        eprintln!("Failed to parse zone file. {e}");
        std::process::exit(1);
    };
    zone.unwrap()
}

fn read_seed_file(seed_file_path: &str) -> Keypair {
    let expanded_path: String = shellexpand::full(seed_file_path).expect("Valid shell path.").into();
    let path = Path::new(&expanded_path);
    let path = PathBuf::from(path);

    let seed = std::fs::read_to_string(path);
    if let Err(e) = seed {
        eprintln!("Failed to read seed at {expanded_path}. {e}");
        std::process::exit(1);
    };
    let seed = seed.unwrap();
    match parse_seed(&seed) {
        Ok(keypair) => keypair,
        Err(e) => {
            eprintln!("Failed to parse the seed file. {e} {seed}");
            std::process::exit(1);
        }
    }
}

/// Parse a seed file into a keypair.
/// Tries to parse as hex first, then as zbase32.
/// Errors if the seed is not valid.
fn parse_seed(seed: &str) -> anyhow::Result<Keypair> {
    let seed = seed.trim();

    if seed.len() == 52 {
        return parse_seed_zbase32(seed);
    }

    parse_seed_hex(seed)
}

/// Parse a hex seed into a keypair.
/// The seed is expected to be 64 characters long.
/// This is the new format of the seed.
fn parse_seed_hex(seed: &str) -> anyhow::Result<Keypair> {
    let decode_result = hex::decode(seed)?;
    let slice: &[u8; SECRET_KEY_LENGTH] = &decode_result[0..SECRET_KEY_LENGTH].try_into()?;
    Ok(Keypair::from_secret_key(slice))
}

/// Parse a zbase32 seed into a keypair.
/// The seed is expected to be 52 characters long.
/// This is the old format of the seed.
fn parse_seed_zbase32(seed: &str) -> anyhow::Result<Keypair> {
    let decode_result = match zbase32::decode_full_bytes_str(seed) {
        Ok(bytes) => bytes,
        Err(_) => return Err(anyhow!("Invalid zbase32 seed")),
    };
    let slice: &[u8; SECRET_KEY_LENGTH] = &decode_result[0..SECRET_KEY_LENGTH].try_into()?;
    Ok(Keypair::from_secret_key(slice))
}

pub async fn cli_publish(matches: &ArgMatches) {
    let seed_file_path: &String = matches.get_one("seed").expect("--seed file path is required");
    let zone_file_path: &String = matches.get_one("zonefile").expect("--zonefile file path is required");

    let keypair = read_seed_file(seed_file_path.as_str());
    let pubkey = keypair.to_z32();
    let client = construct_pkarr_client();

    let zone = read_zone_file(zone_file_path.as_str(), &pubkey).await;
    println!("{}", zone.packet);
    let packet = zone.packet.parsed();
    let packet = SignedPacket::new(&keypair, &packet.answers, Timestamp::now());
    if let Err(e) = packet {
        eprintln!("Failed to sign the pkarr packet. {e}");
        std::process::exit(1);
    }
    let packet = packet.unwrap();

    print!("Hang on... {}", nts_to_chrono(packet.timestamp()));
    std::io::stdout().flush().unwrap();
    let result = client.publish(&packet, None).await;
    print!("\r");
    match result {
        Ok(_) => {
            println!("{} Successfully announced.", nts_to_chrono(packet.timestamp()))
        }
        Err(e) => {
            println!("Error {}", e)
        }
    };
}
