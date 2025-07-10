use clap::ArgMatches;
use pkarr::Keypair;
use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

const SECRET_KEY_LENGTH: usize = 32;

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
    let decode_result = zbase32::decode_full_bytes_str(seed);
    if let Err(e) = decode_result {
        eprintln!("Failed to parse the seed file. {e} {seed}");
        std::process::exit(1);
    };

    let plain_secret = decode_result.unwrap();

    let slice: &[u8; SECRET_KEY_LENGTH] = &plain_secret[0..SECRET_KEY_LENGTH].try_into().unwrap();

    Keypair::from_secret_key(slice)
}

pub async fn cli_publickey(matches: &ArgMatches) {
    let keypair = read_seed_file(matches);
    let pubkey = keypair.to_z32();

    println!("{pubkey}");
}
