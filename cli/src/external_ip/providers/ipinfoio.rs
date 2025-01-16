use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use super::external_ip_resolver::{ExternalIpResolverError, ProviderResolver};

#[derive(Debug, Deserialize)]
struct IpResponse {
    pub ip: String,
}

pub async fn resolve_ipv4() -> Result<Ipv4Addr, ExternalIpResolverError> {
    let response = reqwest::get("https://ipinfo.io").await?;
    let text = response.json::<IpResponse>().await?;
    let ip: Ipv4Addr = text.ip.parse()?;
    Ok(ip)
}

pub async fn resolve_ipv6() -> Result<Ipv6Addr, ExternalIpResolverError> {
    let response = reqwest::get("https://v6.ipinfo.io").await?;
    let text = response.json::<IpResponse>().await?;
    let ip: Ipv6Addr = text.ip.parse()?;
    Ok(ip)
}

pub fn get_resolver() -> ProviderResolver {
    ProviderResolver::new(
        "ipinfo.io".to_string(),
        Box::pin(move || Box::pin(resolve_ipv4())),
        Box::pin(move || Box::pin(resolve_ipv6())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ipv4() {
        let ip = resolve_ipv4().await;
        assert!(ip.is_ok());
    }

    #[ignore = "Github runners don't support ipv6 request."]
    #[tokio::test]
    async fn test_ipv6() {
        let ip = resolve_ipv6().await;
        assert!(ip.is_ok());
    }
}
