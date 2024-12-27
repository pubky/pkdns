use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    time::Duration,
};

use anyhow::anyhow;
use rustdns::{Class, Extension, Message, Resource, Type};

#[derive(Debug)]
pub(crate) struct DomainPortAddr {
    domain: &'static str,
    port: u16,
}

impl DomainPortAddr {
    pub const fn new(domain: &'static str, port: u16) -> Self {
        Self { domain: domain, port }
    }
}

impl std::fmt::Display for DomainPortAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.domain, self.port)
    }
}

pub(crate) static DEFAULT_BOOTSTRAP_NODES: [DomainPortAddr; 4] = [
    DomainPortAddr::new("router.bittorrent.com", 6881),
    DomainPortAddr::new("dht.transmissionbt.com", 6881),
    DomainPortAddr::new("dht.libtorrent.org", 25401),
    DomainPortAddr::new("router.utorrent.com", 6881),
];

/**
 * Resolve the mainline dht boostrap nodes with a custom dns server.
 * Used because if pkdns is set as the system dns on the machine, it can't rely
 * on itself to resolve while starting.
 */
pub(crate) struct MainlineBootstrapResolver {
    socket: UdpSocket,
}

impl MainlineBootstrapResolver {
    pub fn new(dns_server: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::new(5, 0)))?;
        socket.connect(dns_server)?;
        Ok(Self { socket })
    }

    fn lookup_domain(&self, domain: &str) -> Result<Option<IpAddr>, anyhow::Error> {
        let mut m = Message::default();
        m.add_question(domain, Type::A, Class::Internet);
        m.add_extension(Extension {
            // Optionally add a EDNS extension
            payload_size: 4096, // which supports a larger payload size.
            ..Default::default()
        });
        let question = m.to_vec()?;
        self.socket.send(&question)?;

        // Wait for a response from the DNS server.
        let mut resp = [0; 4096];
        let len = self.socket.recv(&mut resp)?;

        // Take the response bytes and turn it into another DNS Message.
        let answer = Message::from_slice(&resp[0..len])?;
        if answer.answers.len() == 0 {
            return Ok(None);
        };
        let first = answer.answers.first().unwrap();
        match first.resource {
            Resource::A(val) => Ok(Some(IpAddr::V4(val))),
            Resource::AAAA(val) => Ok(Some(IpAddr::V6(val))),
            _ => Ok(None),
        }
    }

    fn lookup(&self, boostrap_node: &DomainPortAddr) -> Result<SocketAddr, anyhow::Error> {
        let res = self.lookup_domain(&boostrap_node.domain)?;
        if res.is_none() {
            return Err(anyhow!("No ip found."));
        };
        let ip = res.unwrap();
        Ok(SocketAddr::new(ip, boostrap_node.port))
    }

    pub fn get_bootstrap_nodes(&self) -> Result<Vec<SocketAddr>, anyhow::Error> {
        let mut addrs: Vec<SocketAddr> = vec![];
        for node in DEFAULT_BOOTSTRAP_NODES.iter() {
            match self.lookup(&node) {
                Ok(val) => {
                    addrs.push(val);
                }
                Err(err) => {
                    tracing::trace!("Failed to resolve the DHT bootstrap node domain {node}. {err}");
                }
            }
        }
        if addrs.len() > 0 {
            Ok(addrs)
        } else {
            Err(anyhow!(
                "Failed to resolve the domains of even a single DHT bootstrap node."
            ))
        }
    }

    pub fn get_addrs(dns_server: &SocketAddr) -> Result<Vec<String>, anyhow::Error> {
        let resolver = MainlineBootstrapResolver::new(dns_server.clone()).unwrap();
        let addrs = resolver.get_bootstrap_nodes()?;
        let addrs: Vec<String> = addrs.into_iter().map(|addr| addr.to_string()).collect();
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn query_domain() {
        let google_dns: SocketAddr = "8.8.8.8:53".parse().expect("valid addr");
        let resolver = MainlineBootstrapResolver::new(google_dns).unwrap();
        let res = resolver.lookup_domain("example.com").unwrap().unwrap();
        assert_eq!(res.to_string(), "93.184.215.14");
    }

    #[tokio::test]
    async fn query_bootstrap_node() {
        let google_dns: SocketAddr = "8.8.8.8:53".parse().expect("valid addr");
        let node = DomainPortAddr::new("example.com", 6881);
        let resolver = MainlineBootstrapResolver::new(google_dns).unwrap();
        let res = resolver.lookup(&node).unwrap();
        assert_eq!(res.to_string(), "93.184.215.14:6881");
    }

    #[tokio::test]
    async fn query_bootstrap_nodes() {
        let google_dns: SocketAddr = "8.8.8.8:53".parse().expect("valid addr");
        let resolver = MainlineBootstrapResolver::new(google_dns).unwrap();
        let addrs = resolver.get_bootstrap_nodes().unwrap();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs.first().unwrap().to_string(), "67.215.246.10:6881");
    }
}
