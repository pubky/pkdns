use std::{
    net::SocketAddr, sync::Arc, time::Duration
};
use hickory_server::{resolver::config::NameServerConfigGroup, store::forwarder::{ForwardAuthority, ForwardConfig}};
use hickory_proto::rr::{LowerName, Name, RecordType};
use hickory_server::{authority::Catalog, server::{Request, RequestHandler, ResponseHandler, ResponseInfo}};
use tokio::net::{TcpListener, UdpSocket};

use crate::pkarr_authority::PkarrAuthority;

pub struct DnsServer {
    server: hickory_server::ServerFuture<DnsHandler>,
}

impl DnsServer {
    pub async fn new(dns_handler: DnsHandler) -> Self {
        const TCP_TIMEOUT: Duration = Duration::from_millis(1000);
        let mut server = hickory_server::ServerFuture::new(dns_handler);

        let bind_addr: SocketAddr = "0.0.0.0:53".parse().unwrap();

        let socket = UdpSocket::bind(bind_addr).await.unwrap();

        server.register_socket(socket);
        server.register_listener(TcpListener::bind(bind_addr).await.unwrap(), TCP_TIMEOUT);
        println!("DNS server listening on {}", bind_addr);

        Self { server }
    }

    /// Shutdown the server an wait for all tasks to complete.
    pub async fn shutdown(mut self) {
        self.server.shutdown_gracefully().await.unwrap();
    }

    /// Wait for all tasks to complete.
    ///
    /// Runs forever unless tasks fail.
    pub async fn run_until_done(mut self) {
        self.server.block_until_done().await.unwrap();
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

pub struct DnsHandler {
    catalog: Arc<Catalog>
}

impl DnsHandler {
    pub async fn new() -> Self {
        let mut catalog = Catalog::new();


        let root_name = Name::from_str_relaxed(".").unwrap();
        let forward_config = ForwardConfig {
            name_servers: NameServerConfigGroup::google(),
            options: None
        };
        let forward_auth = ForwardAuthority::try_from_config(
            root_name.clone(), hickory_server::authority::ZoneType::Forward, &forward_config).unwrap();
        let forward_auth = Arc::new(forward_auth);
        catalog.upsert(LowerName::from(root_name), Box::new(Arc::clone(&forward_auth)));

        let pkarr_auth = PkarrAuthority::new().await;
        let pkarr_auth = Arc::new(pkarr_auth);
        catalog.upsert(pkarr_auth.first_origin().clone(), Box::new(Arc::clone(&pkarr_auth)));


        Self{
            catalog: Arc::new(catalog)
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let lookup_name = request.query().name();
        let record_type: RecordType = request.query().query_type();
        
        println!("{} {}", lookup_name, record_type);
        println!("handle_request");
        let res = self.catalog.handle_request(request, response_handle).await;
        res
    }
}
