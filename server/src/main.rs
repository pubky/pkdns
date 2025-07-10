use clap::Parser;
use config::{read_or_create_config, read_or_create_from_dir, update_global_config};
use dns_over_https::run_doh_server;
use helpers::{enable_logging, set_full_stacktrace_as_default, wait_on_ctrl_c};
use resolution::DnsSocketBuilder;

use std::{error::Error, net::SocketAddr, path::PathBuf};

mod config;
mod dns_over_https;
mod helpers;
mod resolution;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "pkdns - A DNS server for Public Key Domains (PDK) hosted on the Mainline DHT."
)]
struct Cli {
    /// ICANN fallback DNS server. Format: IP:Port. [default: 8.8.8.8:53]
    #[arg(short, long)]
    forward: Option<SocketAddr>,

    /// Show verbose output. [default: false]
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verbose: Option<bool>,

    /// The path to pkdns configuration file. This will override the pkdns-dir config path.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// The base directory that contains pkdns's data, configuration file, etc.
    #[arg(short, long, default_value = "~/.pkdns")]
    pkdns_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    set_full_stacktrace_as_default();
    let cli = Cli::parse();

    // Read config file
    let mut config = match cli.config {
        Some(config_path) => read_or_create_config(&config_path).expect("Failed to read valid config file"),
        None => read_or_create_from_dir(&cli.pkdns_dir).expect("Failed to read valid config file"),
    };

    // Override config args if given by CLI
    if let Some(value) = cli.forward {
        config.general.forward = value;
    };
    if let Some(value) = cli.verbose {
        if value {
            config.general.verbose = true
        }
    };

    update_global_config(config.clone());

    enable_logging(config.general.verbose);
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    tracing::info!("Starting pkdns v{VERSION}");
    tracing::debug!("Configuration:\n{}", toml::to_string(&config)?);
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
        .icann_cache_mb(config.dns.icann_cache_mb)
        .pkarr_cache_mb(config.dht.dht_cache_mb)
        .min_ttl(config.dns.min_ttl)
        .max_ttl(config.dns.max_ttl)
        .max_dht_queries_per_ip_per_second(config.dht.dht_query_rate_limit)
        .max_dht_queries_per_ip_burst(config.dht.dht_query_rate_limit_burst)
        .max_queries_per_ip_per_second(config.dns.query_rate_limit)
        .max_queries_per_ip_burst(config.dns.query_rate_limit_burst)
        .top_level_domain(config.dht.top_level_domain)
        .max_recursion_depth(config.dns.max_recursion_depth)
        .build()
        .await?;

    let join_handle = dns_socket.start_receive_loop();

    tracing::info!("Listening on {}. Waiting for Ctrl-C...", config.general.socket);

    if let Some(http_socket) = config.general.dns_over_http_socket {
        run_doh_server(http_socket, dns_socket).await?;
        tracing::info!("[EXPERIMENTAL] DNS-over-HTTP listening on http://{http_socket}/dns-query.");
    };

    wait_on_ctrl_c().await;
    println!();
    tracing::info!("Got it! Exiting...");
    join_handle
        .send(())
        .expect("Failed to send shutdown signal to DNS socket."); // If this fails, we panic as we are already trying to exit.

    Ok(())
}
