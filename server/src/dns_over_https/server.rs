//! RFC8484 Dns-over-http wireformat
//! https://datatracker.ietf.org/doc/html/rfc8484
//! The implementation works but could implement the standard more accurately,
//! especially when it comes to cache-control.

use crate::resolution::DnsSocket;
use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, Method, Response, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use pkarr::dns::Packet;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tower_http::cors::{Any, CorsLayer};

/// Error prefix for web browsers so users actually
/// know what this url is about.
const ERROR_PREFIX: &str = "
Hello to pkdns DNS-over-HTTPS!
https://github.com/pubky/pkdns

Add this DNS url to your browsers to enable self-sovereign Public Key Domains (PKD).





dev:";

/// Validates the accept header.
/// Returns an error if the accept header is missing or not application/dns-message.
fn validate_accept_header(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let error: Result<(), (StatusCode, String)> = Err((
        StatusCode::BAD_REQUEST,
        format!("{ERROR_PREFIX} valid accept header missing"),
    ));
    let accept_header = match headers.get("accept") {
        Some(value) => value,
        None => return error,
    };

    let value_str = match accept_header.to_str() {
        Ok(value) => value,
        Err(_) => return error,
    };

    if value_str != "application/dns-message" {
        return error;
    }
    Ok(())
}

fn decode_dns_base64_packet(param: &String) -> Result<Vec<u8>, (StatusCode, String)> {
    let bytes = match URL_SAFE_NO_PAD.decode(param) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Error decoding the dns base64 query parameter. {e}"),
            ));
        }
    };

    if let Err(e) = Packet::parse(&bytes) {
        tracing::info!("Failed to parse the base64 as a valid dns packet. {e}");
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Failed to parse the base64 as a valid dns packet. {e}"),
        ));
    }
    Ok(bytes)
}

/// Extract lowest ttl of answer to set caching parameter
fn get_lowest_ttl(reply: &[u8]) -> u32 {
    const DEFAULT_VALUE: u32 = 300;

    let parsed_packet = match Packet::parse(reply) {
        Ok(parsed) => parsed,
        Err(_) => return DEFAULT_VALUE,
    };

    let val = parsed_packet
        .answers
        .iter()
        .map(|answer| answer.ttl)
        .reduce(std::cmp::min);

    val.unwrap_or(DEFAULT_VALUE)
}

/// Extracts the client IP for rate limiting.
/// Uses the "x-forwarded-for" header to support proxies.
/// If not available, uses the client IP directly.
fn extract_client_ip(request_addr: &SocketAddr, headers: &HeaderMap) -> IpAddr {
    let origin_ip = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(value) => value,
        None => return request_addr.ip(),
    };

    match origin_ip.parse() {
        Ok(ip) => ip,
        Err(e) => {
            tracing::debug!("Failed to parse the 'x-forwarded-for' header ip address. {e}");
            request_addr.ip()
        }
    }
}

async fn query_to_response(query: Vec<u8>, dns_socket: &mut DnsSocket, client_ip: IpAddr) -> Response<Body> {
    let reply = dns_socket.query_me_recursively_raw(query, Some(client_ip)).await;
    let lowest_ttl = get_lowest_ttl(&reply);

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::CONTENT_LENGTH, reply.len())
        .header(header::CACHE_CONTROL, format!("max-age={lowest_ttl}"))
        .body(Body::from(reply))
        .expect("Failed to build response");

    response
}

async fn dns_query_get(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let client_ip = extract_client_ip(&client_addr, &headers);
    validate_accept_header(&headers)?;

    let dns_param = match params.get("dns") {
        Some(value) => value,
        None => return Err((StatusCode::BAD_REQUEST, "valid dns query param required".to_string())),
    };
    let packet_bytes = decode_dns_base64_packet(dns_param)?;

    let mut socket = state.socket.clone();
    Ok(query_to_response(packet_bytes, &mut socket, client_ip).await)
}

async fn dns_query_post(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let client_ip = extract_client_ip(&client_addr, &headers);
    validate_accept_header(&headers)?;

    let packet_bytes = match axum::body::to_bytes(request.into_body(), 65535usize).await {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => return Err((StatusCode::BAD_REQUEST, e.to_string())),
    };

    let mut socket = state.socket.clone();
    Ok(query_to_response(packet_bytes, &mut socket, client_ip).await)
}

pub struct AppState {
    pub socket: DnsSocket,
}

fn create_app(dns_socket: DnsSocket) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    Router::new()
        .route("/dns-query", get(dns_query_get))
        .route("/dns-query", post(dns_query_post))
        .layer(cors)
        .with_state(Arc::new(AppState { socket: dns_socket }))
}

pub async fn run_doh_server(addr: SocketAddr, dns_socket: DnsSocket) -> Result<SocketAddr, anyhow::Error> {
    let app = create_app(dns_socket);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::{app_context::AppContext, dns_over_https::server::create_app, resolution::DnsSocket};
    use axum_test::TestServer;
    use pkarr::dns::{Name, Packet, PacketFlag, Question};
    use tracing_test::traced_test;

    #[traced_test]
    #[tokio::test]
    async fn query_doh_wireformat_get() {
        // RFC8484 example https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        let context = AppContext::test();
        let socket = DnsSocket::new(&context).await.unwrap();
        let join_handle = socket.start_receive_loop();
        let app = create_app(socket);
        let server = TestServer::new(app.into_make_service_with_connect_info::<SocketAddr>()).unwrap();
        let base64 = "AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJlbC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1zdGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ";
        let response = server
            .get("/dns-query")
            .add_query_param("dns", base64)
            .add_header("accept", "application/dns-message")
            .await;

        response.assert_status_ok();
        assert_eq!(
            response.maybe_header("content-type").expect("content-type available"),
            "application/dns-message"
        );
        assert_eq!(
            response
                .maybe_header("content-length")
                .expect("content-length available"),
            "94"
        );

        let reply_bytes = response.into_bytes();
        let packet = Packet::parse(&reply_bytes).expect("Should be valid packet");
        // dbg!(&packet);
        assert_eq!(packet.answers.len(), 0);
        assert_eq!(packet.name_servers.len(), 0);
        assert_eq!(packet.additional_records.len(), 0);
        assert!(packet.has_flags(PacketFlag::RESPONSE));
        join_handle.send(()).unwrap();
    }

    #[traced_test]
    #[tokio::test]
    async fn query_doh_wireformat_post() {
        let context = AppContext::test();
        let socket = DnsSocket::new(&context).await.unwrap();
        let join_handle = socket.start_receive_loop();
        let app = create_app(socket);
        let server = TestServer::new(app.into_make_service_with_connect_info::<SocketAddr>()).unwrap();

        let mut query = Packet::new_query(50);
        let question = Question::new(
            Name::new_unchecked("example.com"),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            false,
        );
        query.questions.push(question);
        let bytes = query.build_bytes_vec().unwrap();
        let response = server
            .post("/dns-query")
            .add_header("accept", "application/dns-message")
            .bytes(bytes.into())
            .await;

        response.assert_status_ok();
        assert_eq!(
            response.maybe_header("content-type").expect("content-type available"),
            "application/dns-message"
        );

        let content_length_header = response
            .maybe_header("content-length")
            .expect("content-length available");
        let reply_bytes = response.into_bytes();
        assert_eq!(content_length_header, format!("{}", reply_bytes.len()));
        let packet = Packet::parse(&reply_bytes).expect("Should be valid packet");
        assert!(packet.answers.len() > 1);
        join_handle.send(()).unwrap();
    }

    #[tokio::test]
    async fn wrong_content_type() {
        // RFC8484 example https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        let context = AppContext::test();
        let socket = DnsSocket::new(&context).await.unwrap();
        socket.start_receive_loop();
        let app = create_app(socket);
        let server = TestServer::new(app.into_make_service_with_connect_info::<SocketAddr>()).unwrap();
        let base64 = "AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJlbC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1zdGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ";
        let response = server
            .get("/dns-query")
            .add_query_param("dns", base64)
            .add_header("accept", "application/wrong_type")
            .await;

        response.assert_status_bad_request();
    }
}
