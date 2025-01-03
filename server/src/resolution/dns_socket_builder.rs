#![allow(unused)]

use std::{net::SocketAddr, num::{NonZeroI64, NonZeroU32, NonZeroU64}, sync::mpsc::channel};

use super::dns_socket::DnsSocket;

pub struct DnsSocketBuilder {
    /// Forward DNS resolver
    icann_resolver: SocketAddr,

    /// Listening address and port
    listen: SocketAddr,

    /// Maximum number of dns queries one IP address can make per second. 0 = disabled.
    max_queries_per_ip_per_second: u32,

    /// Burst size. 0 = disabled.
    max_queries_per_ip_burst_size: u32,

    /// Maximum number of seconds before a cached value gets auto-refreshed.
    max_ttl: u64,

    /// Minimum number of seconds a value is cached for before being refreshed.
    min_ttl: u64,

    /// Maximum size of the pkarr packet cache in megabytes.
    cache_mb: NonZeroU64,

    /// Maximum number of DHT queries one IP address can make per second. 0 = disabled.
    max_dht_queries_per_ip_per_second: u32,

    /// Burst size of the rate limit. 0 = disabled.
    max_dht_queries_per_ip_burst: u32,
}

impl DnsSocketBuilder {
    pub fn new() -> Self {
        Self {
            icann_resolver: SocketAddr::from(([8, 8, 8, 8], 53)),
            listen: SocketAddr::from(([0, 0, 0, 0], 53)),
            max_queries_per_ip_per_second: 0,
            max_queries_per_ip_burst_size: 0,
            max_ttl: 60 * 60 * 24, // 1 day
            min_ttl: 60 * 1,
            cache_mb: NonZeroU64::new(100).unwrap(),
            max_dht_queries_per_ip_per_second: 0,
            max_dht_queries_per_ip_burst: 0,
        }
    }

    /// Rate limit the number of queries coming from a single IP address.
    pub fn max_queries_per_ip_per_second(mut self, limit: u32) -> Self {
        self.max_queries_per_ip_per_second = limit;
        self
    }

    /// Rate limit burst size
    pub fn max_queries_per_ip_burst(mut self, burst_size: u32) -> Self {
        self.max_queries_per_ip_burst_size = burst_size;
        self
    }

    /// Set the DNS resolver for normal ICANN domains. Defaults to 192.168.1.1:53
    pub fn icann_resolver(mut self, icann_resolver: SocketAddr) -> Self {
        self.icann_resolver = icann_resolver;
        self
    }

    /// Set socket the server should listen on. Defaults to 0.0.0.0:53
    pub fn listen(mut self, listen: SocketAddr) -> Self {
        self.listen = listen;
        self
    }

    /// Maximum cache ttl of pkarr records
    pub fn max_ttl(mut self, rate_s: u64) -> Self {
        self.max_ttl = rate_s;
        self
    }

    /// Minimum cache ttl of pkarr records
    pub fn min_ttl(mut self, rate_s: u64) -> Self {
        self.min_ttl = rate_s;
        self
    }

    /// pkarr cache size
    pub fn cache_mb(mut self, megabytes: NonZeroU64) -> Self {
        self.cache_mb = megabytes;
        self
    }

    /// Rate the number of DHT queries by ip addresses.
    pub fn max_dht_queries_per_ip_per_second(mut self, limit: u32) -> Self {
        self.max_dht_queries_per_ip_per_second = limit;
        self
    }

    /// Burst size of the rate limit.
    pub fn max_dht_queries_per_ip_burst(mut self, burst: u32) -> Self {
        self.max_dht_queries_per_ip_burst = burst;
        self
    }

    /// Build the server.
    pub async fn build(self) -> tokio::io::Result<DnsSocket> {
        DnsSocket::new(
            self.listen,
            self.icann_resolver,
            self.max_queries_per_ip_per_second,
            self.max_queries_per_ip_burst_size,
            self.max_dht_queries_per_ip_per_second,
            self.max_dht_queries_per_ip_burst,
            self.min_ttl,
            self.max_ttl,
            self.cache_mb,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, thread::sleep, time::Duration};

    use crate::resolution::DnsSocket;

    #[tokio::test]
    async fn run() {
        let dns = DnsSocket::default().await.unwrap();
        let join_handle = dns.start_receive_loop();
        println!("Started");
        sleep(Duration::from_secs(5));
        println!("Stop");
        join_handle.abort();
        println!("Stopped");
    }
}
