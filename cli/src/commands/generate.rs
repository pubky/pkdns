use clap::ArgMatches;
use pkarr::Keypair;

pub async fn cli_generate_seed(_matches: &ArgMatches) {
    let keypair = Keypair::random();
    let encoded = hex::encode(keypair.secret_key());
    println!("{encoded}");
}
