use clap::Parser;
use dns_over_https::run_doh_server;
use helpers::{enable_logging, set_full_stacktrace_as_default, wait_on_ctrl_c};

use std::{error::Error, net::SocketAddr, path::PathBuf};

use crate::{app_context::AppContext, config::PersistentDataDir, resolution::DnsSocket};

mod app_context;
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

    /// The base directory that contains pkdns's data, configuration file, etc.
    #[arg(short, long, default_value = "~/.pkdns")]
    pkdns_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    set_full_stacktrace_as_default();
    let cli = Cli::parse();

    let data_dir = PersistentDataDir::new(cli.pkdns_dir);
    let mut app_context = AppContext::from_data_dir(data_dir)?;
    if let Some(verbose) = cli.verbose {
        app_context.config.general.verbose = verbose;
    }
    if let Some(forward) = cli.forward {
        app_context.config.general.forward = forward;
    }

    enable_logging(app_context.config.general.verbose);
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    tracing::info!("Starting pkdns v{VERSION}");
    tracing::debug!("Configuration:\n{:?}", app_context.config);
    tracing::info!("Forward ICANN queries to {}", app_context.config.general.forward);

    // Exit the main thread if anything panics
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        tracing::error!("Thread paniced. Stop main thread too.");
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    let dns_socket = DnsSocket::new(&app_context).await?;

    let join_handle = dns_socket.start_receive_loop();

    tracing::info!(
        "Listening on {}. Waiting for Ctrl-C...",
        app_context.config.general.socket
    );

    if let Some(http_socket) = &app_context.config.general.dns_over_http_socket {
        let socket = run_doh_server(*http_socket, dns_socket).await?;
        tracing::info!("[EXPERIMENTAL] DNS-over-HTTP listening on http://{socket}/dns-query.");
    };

    wait_on_ctrl_c().await;
    println!();
    tracing::info!("Got it! Exiting...");
    join_handle
        .send(())
        .expect("Failed to send shutdown signal to DNS socket."); // If this fails, we panic as we are already trying to exit.

    Ok(())
}
