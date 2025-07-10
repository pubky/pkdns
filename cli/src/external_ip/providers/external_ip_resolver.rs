use std::{
    future::Future,
    net::{AddrParseError, Ipv4Addr, Ipv6Addr},
    pin::Pin,
};

use reqwest::IntoUrl;

type ExternalIpResult<T> = Result<T, ExternalIpResolverError>;

type IpFuture<T> = Pin<Box<dyn Future<Output = ExternalIpResult<T>>>>;

type IpResolver<T> = Pin<Box<dyn Fn() -> IpFuture<T>>>;

pub struct ProviderResolver {
    pub name: String,
    ipv4: IpResolver<Ipv4Addr>,
    ipv6: IpResolver<Ipv6Addr>,
}

impl ProviderResolver {
    pub fn new(name: String, ipv4: IpResolver<Ipv4Addr>, ipv6: IpResolver<Ipv6Addr>) -> Self {
        Self { name, ipv4, ipv6 }
    }

    /// Resolve this computers external ipv4 address.
    pub async fn ipv4(&self) -> Result<Ipv4Addr, ExternalIpResolverError> {
        let func = &self.ipv4;
        func().await
    }

    /// Resolve this computers external ipv6 address.
    pub async fn ipv6(&self) -> Result<Ipv6Addr, ExternalIpResolverError> {
        let func = &self.ipv6;
        func().await
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ExternalIpResolverError {
    #[error(transparent)]
    IO(#[from] reqwest::Error),

    #[error(transparent)]
    IpParse(#[from] AddrParseError),
}

/// Resolves a url return the Ipv4 in it's response.
pub async fn resolve_ipv4_with_url<T: IntoUrl>(url: T) -> Result<Ipv4Addr, ExternalIpResolverError> {
    let response = reqwest::get(url).await?;
    let text = response.text().await?;
    let text = text.trim();
    let ip: Ipv4Addr = text.parse()?;
    Ok(ip)
}

/// Resolves a url return the Ipv6 in it's response.
pub async fn resolve_ipv6_with_url<T: IntoUrl>(url: T) -> Result<Ipv6Addr, ExternalIpResolverError> {
    let response = reqwest::get(url).await?;
    let text = response.text().await?;
    let text = text.trim();
    let ip: Ipv6Addr = text.parse()?;
    Ok(ip)
}
