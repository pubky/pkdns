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
        Self { domain, port }
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

#[derive(Debug, thiserror::Error)]
pub enum MainlineBootstrapResolverError {
    #[error("Failed to resolve any of the boostrap node domains")]
    DomainResolutionFailed,

    #[error("Failed to create a network socket. {0}")]
    SocketError(#[from] std::io::Error),
}

/// Resolve the mainline dht boostrap nodes with a custom dns server.
/// Used because if pkdns is set as the system dns on the machine, it can't rely
/// on itself to resolve while starting.
pub(crate) struct MainlineBootstrapResolver {
    socket: UdpSocket,
}

impl MainlineBootstrapResolver {
    pub fn new(dns_server: SocketAddr) -> Result<Self, MainlineBootstrapResolverError> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::new(3, 0)))?;
        socket.connect(dns_server)?;
        Ok(Self { socket })
    }

    /// Lookup a domain and return the first A record.
    fn lookup_domain(&self, domain: &str) -> Result<Option<IpAddr>, MainlineBootstrapResolverError> {
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
        let reply = Message::from_slice(&resp[0..len])?;
        let first_answer = match reply.answers.first() {
            Some(answer) => answer,
            None => return Ok(None),
        };

        match first_answer.resource {
            Resource::A(val) => Ok(Some(IpAddr::V4(val))),
            _ => Ok(None),
        }
    }

    /// Lookup the domain of the boostrap node and return a SocketAddr.
    fn lookup(&self, boostrap_node: &DomainPortAddr) -> Result<Option<SocketAddr>, MainlineBootstrapResolverError> {
        let res = self.lookup_domain(boostrap_node.domain)?;
        Ok(res.map(|ip| SocketAddr::new(ip, boostrap_node.port)))
    }

    /// Lookup all the bootstrap nodes and return a list of SocketAddrs.
    pub fn get_bootstrap_nodes(&self) -> Result<Vec<SocketAddr>, MainlineBootstrapResolverError> {
        let mut addrs: Vec<SocketAddr> = vec![];
        for node in DEFAULT_BOOTSTRAP_NODES.iter() {
            match self.lookup(node) {
                Ok(Some(val)) => {
                    addrs.push(val);
                }
                Ok(None) => {
                    tracing::debug!("Failed to resolve the DHT bootstrap node domain {node}. No ip found.");
                }
                Err(err) => {
                    tracing::trace!("Failed to resolve the DHT bootstrap node domain {node}. {err}");
                }
            }
        }
        if !addrs.is_empty() {
            Ok(addrs)
        } else {
            Err(MainlineBootstrapResolverError::DomainResolutionFailed)
        }
    }

    /// Lookup all the bootstrap nodes and return a list of Strings.
    pub fn get_addrs(dns_server: &SocketAddr) -> Result<Vec<SocketAddr>, MainlineBootstrapResolverError> {
        let resolver = MainlineBootstrapResolver::new(*dns_server).unwrap();
        let addrs = resolver.get_bootstrap_nodes()?;
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
        let res = resolver.lookup_domain("example.com").unwrap().expect("Valid ip");
    }

    #[tokio::test]
    async fn query_bootstrap_node() {
        let google_dns: SocketAddr = "8.8.8.8:53".parse().expect("valid addr");
        let node = DomainPortAddr::new("example.com", 6881);
        let resolver = MainlineBootstrapResolver::new(google_dns).unwrap();
        let res = resolver.lookup(&node).expect("Valid ip address resolved").unwrap();
        assert_eq!(res.port(), 6881);
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
