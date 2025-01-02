use config::{read_or_create_config, read_or_create_from_dir};
use dns_over_https::run_doh_server;
use helpers::{enable_logging, set_full_stacktrace_as_default, wait_on_ctrl_c};
use resolution::DnsSocketBuilder;

use std::error::Error;

mod dns_over_https;
mod helpers;
mod resolution;
mod config;



#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    set_full_stacktrace_as_default();
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    let cmd = clap::Command::new("pkdns")
        .about("A DNS server for Public Key Domains (PDK).")
        .version(VERSION)
        .arg(
            clap::Arg::new("forward")
                .short('f')
                .long("forward")
                .required(false)
                .default_value("8.8.8.8:53")
                .help("ICANN fallback DNS server. IP:Port"),
        )
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .required(false)
                .num_args(0)
                .help("Show verbose output."),
        ).arg(
            clap::Arg::new("pkdns-dir")
                .short('d')
                .long("pkdnsdir")
                .required(false)
                .default_value("~/.pkdns")
                .help("The base directory that contains pkdns's data, configuration file, etc."),
        ).arg(
            clap::Arg::new("config")
                .short('c')
                .long("config")
                .required(false)
                .help("The path to pkdns configuration file. This will override the pkdnsdir config path."),
        );

    let matches = cmd.get_matches();

    let pkdns_dir: &String = matches.get_one("pkdns-dir").unwrap();
    let config_path: Option<&String> = matches.get_one("config");
    let mut config = match config_path {
        Some(config_path) => {
            read_or_create_config(config_path).expect("Failed to read valid config file")
        },
        None => {
            read_or_create_from_dir(&pkdns_dir.as_str()).expect("Failed to read valid config file")
        },
    };

    config.general.verbose = *matches.get_one("verbose").unwrap();
    let forward: &String = matches.get_one("forward").unwrap();
    config.general.forward = forward.parse().expect("forward should be valid IP:Port combination.");


    enable_logging(config.general.verbose);


    tracing::info!("Starting pkdns v{VERSION}");
    tracing::debug!("Configuration:\n{}", toml::to_string(&config).unwrap());
    tracing::info!("Forward ICANN queries to {}", config.general.forward);

    // Exit the main thread if anything panics
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        tracing::error!("Thread paniced. Stop main thread too.");
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    let dns_socket = DnsSocketBuilder::new()
        .listen(config.general.socket)
        .icann_resolver(config.general.forward)
        .cache_mb(config.dht.cache_mb)
        .min_ttl(config.dns.min_ttl)
        .max_ttl(config.dns.max_ttl)
        .max_dht_queries_per_ip_per_second(config.dht.dht_query_rate_limit)
        .max_dht_queries_per_ip_burst(config.dht.dht_query_rate_limit_burst)
        .max_queries_per_ip_per_second(config.dns.query_rate_limit)
        .max_queries_per_ip_burst(config.dns.query_rate_limit_burst)
        .build()
        .await?;

    let join_handle = dns_socket.start_receive_loop();

    tracing::info!("Listening on {}. Waiting for Ctrl-C...", config.general.socket);

    if let Some(http_socket) = config.general.dns_over_http_socket {
        run_doh_server(http_socket, dns_socket).await;
        tracing::info!("[EXPERIMENTAL] DNS-over-HTTP listening on http://{http_socket}/dns-query.");
    };

    wait_on_ctrl_c().await;
    println!();
    tracing::info!("Got it! Exiting...");
    join_handle.abort();

    Ok(())
}
