use any_dns::{Builder, CustomHandler};
use ctrlc;
use pkarr::dns::Packet;
use pknames_resolver::PknamesResolver;
use std::{error::Error, net::SocketAddr, sync::mpsc::channel, time::Instant};

mod pkarr_cache;
mod pkarr_resolver;
mod pknames_resolver;

#[derive(Clone)]
struct MyHandler {
    pub pkarr: PknamesResolver,
}

impl MyHandler {
    pub fn new(max_cache_ttl: u64, config_dir_path: &str) -> Self {
        Self {
            pkarr: PknamesResolver::new(max_cache_ttl, config_dir_path),
        }
    }
}

impl CustomHandler for MyHandler {
    fn lookup(&mut self, query: &Vec<u8>) -> std::prelude::v1::Result<Vec<u8>, Box<dyn Error>> {
        let start = Instant::now();
        let result = self.pkarr.resolve(query);
        if result.is_ok() {
            let query = Packet::parse(&query).unwrap();
            println!(
                "Resolved {:?} within {}ms",
                query.questions.first().unwrap(),
                start.elapsed().as_millis()
            );
        };

        result
    }
}

fn wait_on_ctrl_c() {
    let (tx, rx) = channel();
    ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
        .expect("Error setting Ctrl-C handler");
    rx.recv().expect("Could not receive from channel.");
}

fn main() -> Result<(), Box<dyn Error>> {
    const VERSION: &str = env!("CARGO_PKG_VERSION");

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
            clap::Arg::new("no-cache")
                .long("no-cache")
                .required(false)
                .num_args(0)
                .help("Disable DHT packet caching."),
        )
        .arg(
            clap::Arg::new("threads")
                .long("threads")
                .required(false)
                .default_value("4")
                .help("Number of threads to process dns queries."),
        )        
        .arg(
            clap::Arg::new("directory")
                .short('d')
                .long("directory")
                .required(false)
                .help("pknames source directory.")
                .default_value("~/.pknames"),
        );

    let matches = cmd.get_matches();
    let verbose: bool = *matches.get_one("verbose").unwrap();
    let no_cache: bool = *matches.get_one("no-cache").unwrap();
    let directory: &String = matches.get_one("directory").unwrap();
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
        println!("Verbose mode");
    }
    if no_cache {
        println!("Disabled DHT cache")
    }
    if threads != 4 {
        println!("Use {} threads", threads);
    }
    if directory != "~/.pknames" {
        println!("Use pknames directory {}", directory);
    }
    if forward.to_string() != "192.168.1.1:53" {
        println!("Forward ICANN queries to {}", forward);
    }


    


    let max_ttl = if no_cache {
        1
    } else {
        60*60
    };

    let anydns = Builder::new()
        .handler(MyHandler::new(max_ttl, directory))
        .threads(threads)
        .verbose(verbose)
        .icann_resolver(forward)
        .listen(socket)
        .build();
    println!("Listening on {}. Waiting for Ctrl-C...", socket);

    wait_on_ctrl_c();
    println!("Got it! Exiting...");
    anydns.join();

    Ok(())
}
