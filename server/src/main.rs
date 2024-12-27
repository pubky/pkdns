use dns_over_https::run_doh_server;
use helpers::{enable_logging, set_full_stacktrace_as_default, wait_on_ctrl_c};
use resolution::DnsSocketBuilder;

use std::{
    error::Error,
    net::{AddrParseError, SocketAddr},
    num::NonZeroU32,
};

mod dns_over_https;
mod helpers;
mod resolution;

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
            clap::Arg::new("min-ttl")
                .long("min-ttl")
                .required(false)
                .default_value("60")
                .help("Minimum number of seconds a value is cached for before being refreshed."),
        )
        .arg(
            clap::Arg::new("max-ttl")
                .long("max-ttl")
                .required(false)
                .default_value("86400") // 24hrs
                .help("Maximum number of seconds before a cached value gets auto-refreshed."),
        )
        .arg(
            clap::Arg::new("cache-mb")
                .long("cache-mb")
                .required(false)
                .default_value("100")
                .help("Maximum size of the pkarr packet cache in megabytes."),
        ).arg(
            clap::Arg::new("query-rate-limit")
                .long("query-rate-limit")
                .required(false)
                .default_value("0")
                .help("Maximum number of queries per second one IP address can make before it is rate limited. 0 is disabled."),
        ).arg(
            clap::Arg::new("query-rate-limit-burst")
                .long("query-rate-limit-burst")
                .required(false)
                .default_value("0")
                .help("Short term burst size of the query-rate-limit. 0 is disabled."),
        ).arg(
            clap::Arg::new("dht-rate-limit")
                .long("dht-rate-limit")
                .required(false)
                .default_value("5")
                .help("Maximum number of queries per second one IP address can make to the DHT before it is rate limited. 0 is disabled."),
        ).arg(
            clap::Arg::new("dht-rate-limit-burst")
                .long("dht-rate-limit-burst")
                .required(false)
                .default_value("25")
                .help("Short term burst size of the dht-rate-limit. 0 is disabled."),
        ).arg(
            clap::Arg::new("doh")
                .long("doh")
                .required(false)
                .help("[EXPERIMENTAL] Enables DNS over HTTP on the given socket. Example: 127.0.0.1:3000. Default: Disabled."),
        );

    let matches = cmd.get_matches();
    let verbose: bool = *matches.get_one("verbose").unwrap();
    let max_ttl: &String = matches.get_one("max-ttl").unwrap();
    let max_ttl: u64 = max_ttl
        .parse()
        .expect("max-ttl should be a valid valid positive integer.");
    let min_ttl: &String = matches.get_one("min-ttl").unwrap();
    let min_ttl: u64 = min_ttl
        .parse()
        .expect("min-ttl should be a valid valid positive integer.");
    let cache_mb: &String = matches.get_one("cache-mb").unwrap();
    let cache_mb: u64 = cache_mb
        .parse()
        .expect("cache-mb should be a valid valid positive integer of at least 1.");
    let forward: &String = matches.get_one("forward").unwrap();
    let mut forward: String = forward.clone();
    if !forward.contains(":") {
        forward.push_str(":53"); // Add default port
    };
    let forward: SocketAddr = forward.parse().expect("forward should be valid IP:Port combination.");
    let socket: &String = matches.get_one("socket").unwrap();
    let socket: SocketAddr = socket.parse().expect("socket should be valid IP:Port combination.");

    let query_rate_limit: &String = matches.get_one("query-rate-limit").unwrap();
    let query_rate_limit: u32 = query_rate_limit.parse().expect("query-rate-limit must be a >=0.");
    let query_rate_limit_burst: &String = matches.get_one("query-rate-limit-burst").unwrap();
    let query_rate_limit_burst: u32 = query_rate_limit_burst
        .parse()
        .expect("query-rate-limit-burst must be a >=0.");
    let dht_rate_limit: &String = matches.get_one("dht-rate-limit").unwrap();
    let dht_rate_limit: u32 = dht_rate_limit.parse().expect("dht-rate-limit must be a >=0.");
    let dht_rate_limit_burst: &String = matches.get_one("dht-rate-limit-burst").unwrap();
    let dht_rate_limit_burst: u32 = dht_rate_limit_burst
        .parse()
        .expect("dht-rate-limit-burst must be a >=0.");

    let doh: Option<SocketAddr> = match matches.get_one("doh") {
        Some(value) => {
            let val: &String = value;
            let socket: Result<SocketAddr, AddrParseError> = val.parse();
            match socket {
                Ok(s) => Some(s),
                Err(e) => panic!("doh socket parse failed. {e} Expected ip:port combination."),
            }
        }
        None => None,
    };

    enable_logging(verbose);

    if cache_mb <= 0 {
        tracing::error!("--cache-mb must be at least 1. Given {cache_mb}.")
    }

    tracing::info!("Starting pkdns v{VERSION}");
    tracing::debug!("min_ttl={min_ttl} max_ttl={max_ttl} cache_mb={cache_mb} verbose={verbose} forward={forward} query_rate_limit={query_rate_limit} query_rate_limit_burst={query_rate_limit_burst} dht_rate_limit={dht_rate_limit} dht_rate_limit_burst={dht_rate_limit_burst} doh={doh:?}");

    tracing::info!("Forward ICANN queries to {}", forward);

    // Exit the main thread if a anydns thread panics. Todo: Add to anydns
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        tracing::error!("Thread paniced. Stop main thread too.");
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    let dht_rate_limit_option = match dht_rate_limit {
        0 => None,
        val => Some(NonZeroU32::new(val).unwrap()),
    };
    let dht_rate_limit_burst_option = match dht_rate_limit_burst {
        0 => None,
        val => Some(NonZeroU32::new(val).unwrap()),
    };
    let query_rate_limit_option = match query_rate_limit {
        0 => None,
        val => Some(NonZeroU32::new(val).unwrap()),
    };
    let query_rate_limit_burst_option = match query_rate_limit_burst {
        0 => None,
        val => Some(NonZeroU32::new(val).unwrap()),
    };
    let dns_socket = DnsSocketBuilder::new()
        .listen(socket)
        .icann_resolver(forward)
        .cache_mb(cache_mb)
        .min_ttl(min_ttl)
        .max_ttl(max_ttl)
        .max_dht_queries_per_ip_per_second(dht_rate_limit_option)
        .max_dht_queries_per_ip_burst(dht_rate_limit_burst_option)
        .max_queries_per_ip_per_second(query_rate_limit_option)
        .max_queries_per_ip_burst(query_rate_limit_burst_option)
        .build()
        .await?;

    let join_handle = dns_socket.start_receive_loop();

    tracing::info!("Listening on {socket}. Waiting for Ctrl-C...");

    if let Some(http_socket) = doh {
        run_doh_server(http_socket, dns_socket).await;
        tracing::info!("[EXPERIMENTAL] DNS-over-HTTP listening on http://{http_socket}/dns-query.");
    };

    wait_on_ctrl_c().await;
    println!();
    tracing::info!("Got it! Exiting...");
    join_handle.abort();

    Ok(())
}
