use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use super::external_ip_resolver::{ExternalIpResolverError, ProviderResolver};

#[derive(Debug, Deserialize)]
struct IpResponse {
    pub ip: String,
}

pub async fn resolve_ipv4() -> Result<Ipv4Addr, ExternalIpResolverError> {
    let response = reqwest::get("https://4.myip.is/").await?;
    let text = response.json::<IpResponse>().await?;
    let ip: Ipv4Addr = text.ip.parse()?;
    Ok(ip)
}

pub async fn resolve_ipv6() -> Result<Ipv6Addr, ExternalIpResolverError> {
    let response = reqwest::get("https://6.myip.is/").await?;
    let text = response.json::<IpResponse>().await?;
    let ip: Ipv6Addr = text.ip.parse()?;
    Ok(ip)
}

pub fn get_resolver() -> ProviderResolver {
    ProviderResolver::new(
        "myip.is".to_string(),
        Box::pin(move || Box::pin(resolve_ipv4())),
        Box::pin(move || Box::pin(resolve_ipv6())),
    )
}

#[cfg(test)]
mod tests {
    use crate::external_ip::providers::external_ip_resolver::is_ipv6_available;

    use super::*;

    #[tokio::test]
    async fn test_ipv4() {
        let ip = resolve_ipv4().await;
        ip.expect("Valid ipv4");
    }

    #[tokio::test]
    async fn test_ipv6() {
        if is_ipv6_available() {
            // Only run test if ipv6 is available on this system.
            let ip = resolve_ipv6().await;
            assert!(ip.is_ok());
        }
    }
}
