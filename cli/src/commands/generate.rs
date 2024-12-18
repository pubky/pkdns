use clap::ArgMatches;
use pkarr::Keypair;

pub async fn cli_generate_seed(_matches: &ArgMatches) {
    let keypair = Keypair::random();
    let encoded = zbase32::encode_full_bytes(&keypair.secret_key());
    println!("{encoded}");
}
