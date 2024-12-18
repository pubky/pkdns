#![allow(unused)]

use std::{net::SocketAddr, num::NonZeroU32, sync::mpsc::channel};

use super::{
    custom_handler::{CustomHandler, EmptyHandler, HandlerHolder},
    dns_socket::DnsSocket,
};

pub struct Builder {
    icann_resolver: SocketAddr,
    listen: SocketAddr,
    handler: HandlerHolder,
    max_queries_per_ip_per_second: Option<NonZeroU32>,
    burst_size: Option<NonZeroU32>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            icann_resolver: SocketAddr::from(([192, 168, 1, 1], 53)),
            listen: SocketAddr::from(([0, 0, 0, 0], 53)),
            handler: HandlerHolder::new(EmptyHandler::new()),
            max_queries_per_ip_per_second: None,
            burst_size: None,
        }
    }

    /// Rate limit the number of queries coming from a single IP address.
    pub fn max_queries_per_ip_per_second(mut self, limit: Option<NonZeroU32>) -> Self {
        self.max_queries_per_ip_per_second = limit;
        self
    }

    /// Rate limit burst size
    pub fn max_queries_per_ip_burst(mut self, burst_size: Option<NonZeroU32>) -> Self {
        self.burst_size = burst_size;
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

    /** Set handler to process the dns packet. `Ok()`` should include a dns packet with answers. `Err()` will fallback to ICANN. */
    pub fn handler(mut self, handler: impl CustomHandler + 'static) -> Self {
        self.handler = HandlerHolder::new(handler);
        self
    }

    // /** Build and start server. */
    pub async fn build(self) -> tokio::io::Result<AnyDNS> {
        AnyDNS::new(
            self.listen,
            self.icann_resolver,
            self.handler,
            self.max_queries_per_ip_per_second,
            self.burst_size,
        )
        .await
    }
}

#[derive(Debug)]
pub struct AnyDNS {
    join_handle: tokio::task::JoinHandle<()>,
}

impl AnyDNS {
    pub async fn new(
        listener: SocketAddr,
        icann_fallback: SocketAddr,
        handler: HandlerHolder,
        max_queries_per_ip_per_second: Option<NonZeroU32>,
        burst_size: Option<NonZeroU32>,
    ) -> tokio::io::Result<Self> {
        let mut socket = DnsSocket::new(
            listener,
            icann_fallback,
            handler,
            max_queries_per_ip_per_second,
            burst_size,
        )
        .await?;
        let join_handle = tokio::spawn(async move {
            socket.receive_loop().await;
        });

        let server = Self { join_handle };

        Ok(server)
    }

    /**
     * Stops the server and consumes the instance.
     */
    pub fn stop(self) {
        self.join_handle.abort();
    }

    /**
     * Waits on CTRL+C
     */
    pub async fn wait_on_ctrl_c(&self) {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(err) => {
                eprintln!("Unable to listen for shutdown signal Ctrl+C: {}", err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, thread::sleep, time::Duration};

    use super::super::server::Builder;

    #[tokio::test]
    async fn run() {
        let listening: SocketAddr = "0.0.0.0:34255".parse().unwrap();
        let dns = Builder::new().listen(listening).build().await.unwrap();
        println!("Started");
        sleep(Duration::from_secs(5));
        println!("Stop");
        dns.stop();
        println!("Stopped");
    }
}
