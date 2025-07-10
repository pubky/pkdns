use rand::seq::SliceRandom;
use rand::thread_rng;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::providers::ProviderResolver;
use super::providers::{icanhazip, identme, ipifyorg, ipinfoio, myip};

/// Resolves the external IPv4 address randomly from a list of 5 service providers.
/// Returns IP and the name of the service provider.
pub async fn resolve_ipv4() -> Result<(Ipv4Addr, String), &'static str> {
    let mut providers: Vec<ProviderResolver> = vec![
        icanhazip::get_resolver(),
        identme::get_resolver(),
        ipifyorg::get_resolver(),
        ipinfoio::get_resolver(),
        myip::get_resolver(),
    ];

    let mut rng = thread_rng();
    providers.shuffle(&mut rng);

    for provider in providers {
        match provider.ipv4().await {
            Ok(ip) => return Ok((ip, provider.name.clone())),
            Err(e) => {
                println!("Failed to fetch ip from {}. {e}", provider.name);
            }
        }
    }

    Err("All ip providers failed to return the external ip.")
}

/// Resolves the external IPv6 address randomly from a list of 5 service providers.
/// Returns IP and the name of the service provider.
pub async fn resolve_ipv6() -> Result<(Ipv6Addr, String), &'static str> {
    let mut providers: Vec<ProviderResolver> = vec![
        icanhazip::get_resolver(),
        identme::get_resolver(),
        ipifyorg::get_resolver(),
        ipinfoio::get_resolver(),
        myip::get_resolver(),
    ];

    let mut rng = thread_rng();
    providers.shuffle(&mut rng);

    for provider in providers {
        match provider.ipv6().await {
            Ok(ip) => return Ok((ip, provider.name.clone())),
            Err(e) => {
                println!("Failed to fetch ip from {}. {e}", provider.name);
            }
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

    #[ignore = "Github runners don't support ipv6 request."]
    #[tokio::test]
    async fn test_ipv6() {
        let ip = resolve_ipv6().await;
        println!("{:?}", ip.expect("Valid ipv6"));
    }
}
