use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use rand::thread_rng;
use rand::seq::SliceRandom;
use tokio::sync::{mpsc, Mutex};

use super::providers::ProviderResolver;
use super::providers::{icanhazip, identme, ipifyorg, ipinfoio, myip};


/// Resolves the external IPv4 address randomly from a list of 5 service providers.
/// Returns IP and the name of the service provider.
pub async fn resolve_ipv4() -> Result<(Ipv4Addr, String), &'static str> {
    let mut providers: Vec<ProviderResolver> = vec![];
    providers.push(icanhazip::get_resolver());
    providers.push(identme::get_resolver());
    providers.push(ipifyorg::get_resolver());
    providers.push(ipinfoio::get_resolver());
    providers.push(myip::get_resolver());

    let mut rng = thread_rng();
    providers.shuffle(&mut rng);

    for provider in providers {
        match provider.ipv4().await {
            Ok(ip) => return Ok((ip, provider.name.clone())),
            Err(e) => {
                println!("Failed to fetch ip from {}. {e}", provider.name);
            },
        }
    }

    Err("All ip providers failed to return the external ip.")
}

/// Resolves the external IPv6 address randomly from a list of 5 service providers.
/// Returns IP and the name of the service provider.
pub async fn resolve_ipv6() -> Result<(Ipv6Addr, String), &'static str> {
    let mut providers: Vec<ProviderResolver> = vec![];
    providers.push(icanhazip::get_resolver());
    providers.push(identme::get_resolver());
    providers.push(ipifyorg::get_resolver());
    providers.push(ipinfoio::get_resolver());
    providers.push(myip::get_resolver());

    let mut rng = thread_rng();
    providers.shuffle(&mut rng);

    for provider in providers {
        match provider.ipv6().await {
            Ok(ip) => return Ok((ip, provider.name.clone())),
            Err(e) => {
                println!("Failed to fetch ip from {}. {e}", provider.name);
            },
        }
    }

    Err("All ip providers failed to return the external ip.")
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ipv4() {
        let ip = resolve_ipv4().await;
        println!("{:?}", ip.expect("Valid ipv4"));
    }

    #[tokio::test]
    async fn test_ipv6() {
        let ip = resolve_ipv6().await;
        println!("{:?}", ip.expect("Valid ipv6"));
    }
}
