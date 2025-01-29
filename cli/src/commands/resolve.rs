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



// Resolution test to describe a bug
// #[cfg(test)]
// mod tests {
//     use pkarr::{Keypair, PkarrClientBuilder};

//     use super::*;

//     fn publish_key() {
//         let key = Keypair::random();
//         let client = PkarrClientBuilder::default()
//         .resolvers(None)
//         .build()
//         .unwrap();

//     }

//     #[test]
//     fn test_pkarr_resolve() {
//         for i in 0..10 {
//             let client = PkarrClientBuilder::default()
//             .resolvers(None)
//             .build()
//             .unwrap();
//             thread::sleep(Duration::from_millis(500));

//             let pubkey: PublicKey = "7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy".try_into().unwrap();
//             let val = client.resolve(&pubkey);
//             let val = val.expect("Public key resolution failed.");
//             if val.is_none() {
//                 println!("{i} Not found");
//             } else {
//                 let val = val.unwrap();
//                 let timestamp = DateTime::from_timestamp_micros(val.timestamp() as i64);
//                 println!("{i} Found! {timestamp:?}");
//                 break;
//             }
//         };
//     }

// }
