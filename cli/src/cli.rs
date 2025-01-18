use crate::commands::{cli_publickey, generate::cli_generate_seed, publish::cli_publish, resolve::cli_resolve};

/**
 * Main cli entry function.
 */
pub async fn run_cli() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    let cmd = clap::Command::new("pkarr-cli")
        .version(VERSION)
        .arg_required_else_help(true)
        .subcommand(
            clap::Command::new("publish")
                .about("Publish pkarr dns records.")
                .arg(
                    clap::Arg::new("seed")
                        .help("File path to the pkarr seed file.")
                        .default_value("./seed.txt"),
                )
                .arg(
                    clap::Arg::new("zonefile")
                        .help("File path to the dns zone file.")
                        .default_value("./pkarr.zone"),
                )
                .arg(
                    clap::Arg::new("once")
                        .long("once")
                        .required(false)
                        .num_args(0)
                        .help("File path to the dns records csv file."),
                ),
        )
        .subcommand(
            clap::Command::new("resolve")
                .about("Resolve pkarr dns records.")
                .arg(clap::Arg::new("pubkey").required(false).help("Pkarr public key uri.")),
        )
        .subcommand(clap::Command::new("generate").about("Generate a new zbase32 pkarr seed"))
        .subcommand(
            clap::Command::new("publickey")
                .about("Derive the public key from the seed.")
                .arg(
                    clap::Arg::new("seed")
                        .required(false)
                        .help("File path to the pkarr seed file.")
                        .default_value("./seed.txt"),
                ),
        );
    let matches = cmd.get_matches();

    match matches.subcommand() {
        Some(("resolve", matches)) => {
            cli_resolve(matches).await;
        }
        Some(("publish", matches)) => {
            cli_publish(matches).await;
        }
        Some(("generate", matches)) => {
            cli_generate_seed(matches).await;
        }
        Some(("publickey", matches)) => {
            cli_publickey(matches).await;
        }
        _ => {
            unimplemented!("command not implemented")
        }
    };
}
