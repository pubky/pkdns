use any_dns::{Builder, CustomHandler, CustomHandlerError, DnsSocket};
use async_trait::async_trait;

use pkarr_resolver::PkarrResolver;
use std::{error::Error, net::SocketAddr};

mod packet_lookup;
mod pkarr_cache;
mod pkarr_resolver;

#[derive(Clone)]
struct MyHandler {
    pub pkarr: PkarrResolver,
}

impl MyHandler {
    pub async fn new(max_cache_ttl: u64) -> Self {
        Self {
            pkarr: PkarrResolver::new(max_cache_ttl).await,
        }
    }
}
#[async_trait]
impl CustomHandler for MyHandler {
    async fn lookup(&mut self, query: &Vec<u8>, mut socket: DnsSocket) -> Result<Vec<u8>, CustomHandlerError> {
        let result = self.pkarr.resolve(query, &mut socket).await;

        match result {
            Ok(reply) => Ok(reply),
            Err(_) => Err(CustomHandlerError::Unhandled),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    tracing_subscriber::fmt::init();
    tracing::debug!("Starting pkdns v{VERSION}");

    let cmd = clap::Command::new("pkdns")
        .about("A DNS server for pkarr self-sovereign domains.")
        .version(VERSION)
        .arg(
            clap::Arg::new("forward")
                .short('f')
                .long("forward")
                .required(false)
                .default_value("192.168.1.1:53")
                .help("ICANN fallback DNS server. IP:Port"),
        )
        .arg(
            clap::Arg::new("socket")
                .short('s')
                .long("socket")
                .required(false)
                .default_value("0.0.0.0:53")
                .help("Socket the server should listen on. IP:Port"),
        )
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .required(false)
                .num_args(0)
                .help("Show verbose output."),
        )
        .arg(
            clap::Arg::new("cache-ttl")
                .long("cache-ttl")
                .required(false)
                .help("Pkarr packet cache ttl in seconds."),
        )
        .arg(
            clap::Arg::new("threads")
                .long("threads")
                .required(false)
                .default_value("4")
                .help("Number of threads to process dns queries."),
        );

    let matches = cmd.get_matches();
    let verbose: bool = *matches.get_one("verbose").unwrap();
    let default_cache_ttl = "60".to_string();
    let cache_ttl: &String = matches.get_one("cache-ttl").unwrap_or(&default_cache_ttl);
    let cache_ttl: u64 = cache_ttl
        .parse()
        .expect("cache-ttl should be a valid valid positive integer (u64).");
    let threads: &String = matches.get_one("threads").unwrap();
    let threads: u8 = threads.parse().expect("threads should be valid positive integer.");
    let forward: &String = matches.get_one("forward").unwrap();
    let mut forward: String = forward.clone();
    if !forward.contains(":") {
        forward.push_str(":53"); // Add default port
    };
    let forward: SocketAddr = forward.parse().expect("forward should be valid IP:Port combination.");
    let socket: &String = matches.get_one("socket").unwrap();
    let socket: SocketAddr = socket.parse().expect("socket should be valid IP:Port combination.");

    if verbose {
        tracing::info!("Verbose mode");
    }
    if cache_ttl != 60 {
        tracing::info!("Set cache-ttl to {cache_ttl}s");
    }
    if threads != 4 {
        tracing::info!("Use {threads} threads");
    }

    tracing::info!("Forward ICANN queries to {}", forward);

    // Exit the main thread if a anydns thread panics. Todo: Add to anydns
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        tracing::error!("Thread paniced. Stop main thread too.");
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    let anydns = Builder::new()
        .handler(MyHandler::new(cache_ttl).await)
        .verbose(verbose)
        .icann_resolver(forward)
        .listen(socket)
        .build()
        .await?;
    tracing::info!("Listening on {socket}. Waiting for Ctrl-C...");

    anydns.wait_on_ctrl_c().await;
    println!();
    tracing::info!("Got it! Exiting...");
    anydns.stop();

    Ok(())
}
