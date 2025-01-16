use std::net::{Ipv4Addr, Ipv6Addr};

use super::external_ip_resolver::{
    resolve_ipv4_with_url, resolve_ipv6_with_url, ExternalIpResolverError, ProviderResolver,
};

pub async fn resolve_ipv4() -> Result<Ipv4Addr, ExternalIpResolverError> {
    resolve_ipv4_with_url("https://ipv4.icanhazip.com").await
}

pub async fn resolve_ipv6() -> Result<Ipv6Addr, ExternalIpResolverError> {
    resolve_ipv6_with_url("https://ipv6.icanhazip.com").await
}

pub fn get_resolver() -> ProviderResolver {
    ProviderResolver::new(
        "icanhazip.com".to_string(),
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
        assert!(ip.is_ok());
    }

    #[tokio::test]
    async fn test_ipv6() {
        if is_ipv6_available() { // Only run test if ipv6 is available on this system.
            let ip = resolve_ipv6().await;
            assert!(ip.is_ok());
        }
    }
}
