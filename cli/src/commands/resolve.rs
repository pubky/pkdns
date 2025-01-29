use std::{thread, time::Duration};

use chrono::{DateTime, Utc};
use clap::ArgMatches;
use pkarr::PublicKey;

use crate::{helpers::construct_pkarr_client, pkarr_packet::PkarrPacket};

fn resolve_pkarr(uri: &str) -> (PkarrPacket, DateTime<Utc>) {
    let client = construct_pkarr_client();
    let pubkey: PublicKey = uri.try_into().expect("Should be valid pkarr public key.");
    let res = client.resolve(&pubkey);
    if let Err(e) = res {
        eprintln!("Failed to resolve. {e}");
        std::process::exit(1);
    }
    if let None = res.unwrap() {
        eprintln!("Failed to find the packet on the first try. Try again.");
    }
    thread::sleep(Duration::from_millis(1000));
    let res = client.resolve(&pubkey);
    if let Err(e) = res {
        eprintln!("Failed to resolve. {e}");
        std::process::exit(1);
    }
    let res = res.unwrap();
    if res.is_none() {
        println!("Failed to find the packet on the second try.");
        return (PkarrPacket::empty(), DateTime::<Utc>::MIN_UTC);
    };
    let signed_packet = res.unwrap();
    let timestamp =
        chrono::DateTime::from_timestamp((signed_packet.timestamp() / 1000000).try_into().unwrap(), 0).unwrap();
    let packet = signed_packet.packet();

    let data = packet.build_bytes_vec_compressed().unwrap();

    (PkarrPacket::by_data(data), timestamp)
}

fn get_arg_pubkey(matches: &ArgMatches) -> Option<PublicKey> {
    let uri_arg: &String = matches.get_one("pubkey").unwrap();
    let trying: Result<PublicKey, _> = uri_arg.as_str().try_into();
    trying.ok()
}

pub async fn cli_resolve(matches: &ArgMatches) {
    let pubkey_opt = get_arg_pubkey(matches);

    if pubkey_opt.is_none() {
        eprintln!("pubkey is not a valid pkarr public key.");
        std::process::exit(1);
    };
    let pubkey = pubkey_opt.unwrap();
    let uri = pubkey.to_uri_string();

    println!("Resolve dns records of {}", uri);
    let (packet, timestamp) = resolve_pkarr(&uri);

    println!("{packet}");
    if !packet.is_emtpy() {
        println!("Last updated at: {timestamp}");
    };
}
