<<<<<<< Updated upstream
use std::{fs::read_to_string, path::{Path, PathBuf}};

use chrono::Duration;
=======
>>>>>>> Stashed changes
use clap::ArgMatches;
use pkarr::{Keypair, SignedPacket};
use std::io::Write;
use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use crate::{pkarr_publisher::PkarrPublisher, simple_zone::SimpleZone};

const SECRET_KEY_LENGTH: usize = 32;

fn read_zone_file(matches: &ArgMatches, pubkey: &str) -> SimpleZone {
    let unexpanded_path: &String = matches.get_one("zonefile").unwrap();
    let csv_path_str: String = shellexpand::full(unexpanded_path).expect("Valid shell path.").into();
    let path = Path::new(&csv_path_str);
    let path = PathBuf::from(path);

    let zone = read_to_string(path);
    if let Err(e) = zone {
        eprintln!("Failed to read zone at {csv_path_str}. {e}");
        std::process::exit(1);
    };
    let zone = zone.unwrap();

    let zone = SimpleZone::read(zone, pubkey);
    if let Err(e) = zone {
        eprintln!("Failed to parse zone file. {e}");
        std::process::exit(1);
    };
    zone.unwrap()
}

fn read_seed_file(matches: &ArgMatches) -> Keypair {
    let unexpanded_path: &String = matches.get_one("seed").unwrap();
    let expanded_path: String = shellexpand::full(unexpanded_path).expect("Valid shell path.").into();
    let path = Path::new(&expanded_path);
    let path = PathBuf::from(path);

    let seed = read_to_string(path);
    if let Err(e) = seed {
        eprintln!("Failed to read seed at {expanded_path}. {e}");
        std::process::exit(1);
    };
    let seed = seed.unwrap();
    parse_seed(&seed)
}

fn parse_seed(seed: &str) -> Keypair {
    let seed = seed.trim();
    let decode_result = zbase32::decode_full_bytes_str(&seed);
    if let Err(e) = decode_result {
        eprintln!("Failed to parse the seed file. {e} {seed}");
        std::process::exit(1);
    };

    let plain_secret = decode_result.unwrap();

    let slice: &[u8; SECRET_KEY_LENGTH] = &plain_secret[0..SECRET_KEY_LENGTH].try_into().unwrap();
    let keypair = Keypair::from_secret_key(slice);
    keypair
}

pub async fn cli_publish(matches: &ArgMatches) {
    let keypair = read_seed_file(matches);
    let pubkey = keypair.to_z32();

    let zone = read_zone_file(matches, &pubkey);
    println!("{}", zone.packet);

    let packet = zone.packet.parsed();
    let packet = SignedPacket::from_packet(&keypair, &packet);
    if let Err(e) = packet {
        eprintln!("Failed to sign the pkarr packet. {e}");
        std::process::exit(1);
    }

    let packet = packet.unwrap();

<<<<<<< Updated upstream

    let publisher = PkarrPublisher::new(packet);
    if once {
        println!("Announce once.");
        publisher.run_once();
    } else {
        println!(
            "Announce every {}min. Stop with Ctrl-C...",
            interval.num_minutes()
        );
        publisher.run(interval);
    }
=======
    let client = construct_pkarr_client();
    print!("Hang on...");
    std::io::stdout().flush().unwrap();
    let result = client.publish(&packet);
    print!("\r");
    match result {
        Ok(_) => println!("{} Successfully announced.", packet.timestamp()),
        Err(e) => println!("Error {}", e.to_string()),
    };
>>>>>>> Stashed changes
}
