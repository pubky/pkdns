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
use simple_dns::Packet;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tower_http::cors::{Any, CorsLayer};

/// RFC8484 Dns-over-http wireformat
/// https://datatracker.ietf.org/doc/html/rfc8484
/// The implementation works but could implement the standard more accurately,
/// especially when it comes to cache-control.


/// Error prefix for web browsers so users actually
/// know what this url is about.
const ERROR_PREFIX: &str = "
Hello to pkdns DNS-over-HTTPS!
https://github.com/pubky/pkdns

Add this DNS url to your browsers to enable self-sovereign Public Key Domains (PKD).





dev:";

fn validate_accept_header(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    if let None = headers.get("accept") {
        return Err((StatusCode::BAD_REQUEST, format!("{ERROR_PREFIX} valid accept header missing")));
    };
    let value = headers.get("accept").unwrap();
    if let Err(e) = value.to_str() {
        return Err((StatusCode::BAD_REQUEST, format!("{ERROR_PREFIX} valid accept header missing. {e}")));
    }
    let value = value.to_str().unwrap();
    if value != "application/dns-message" {
        return Err((StatusCode::BAD_REQUEST, format!("{ERROR_PREFIX} valid accept header missing")));
    }
    Ok(())
}

fn decode_dns_base64_packet(param: &String) -> Result<Vec<u8>, (StatusCode, String)> {
    let val = URL_SAFE_NO_PAD.decode(param);
    if let Err(e) = val {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Error decoding the dns base64 query parameter. {e}"),
        ));
    };
    let vec = val.unwrap();
    if let Err(e) = Packet::parse(&vec) {
        tracing::info!("{e}");
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Failed to parse the base64 as a valid dns packet. {e}"),
        ));
    }
    Ok(vec)
}

/// Extract lowest ttl of answer to set caching parameter
fn get_lowest_ttl(reply: &Vec<u8>) -> u32 {
    const DEFAULT_VALUE: u32 = 300;
    let parsed = Packet::parse(reply);
    if let Err(_) = parsed {
        return DEFAULT_VALUE;
    };
    let parsed = parsed.unwrap();
    let val = parsed
        .answers
        .iter()
        .map(|answer| answer.ttl)
        .reduce(|a, b| std::cmp::min(a, b));

    val.unwrap_or(DEFAULT_VALUE)
}

/// Extracts the client IP for rate limiting.
/// Uses the "x-forwarded-for" header to support proxies.
/// If not available, uses the client IP directly.
fn extract_client_ip(request_addr: &SocketAddr, headers: &HeaderMap) -> IpAddr {
    let proxy_x_forwarded_ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    if let None = proxy_x_forwarded_ip {
        return request_addr.ip();
    };

    let proxy_x_forwarded_ip = proxy_x_forwarded_ip.unwrap();
    let ip_parsed: Result<IpAddr, _> = proxy_x_forwarded_ip.parse();
    match ip_parsed {
        Ok(ip) => ip,
        Err(e) => {
            tracing::debug!("Failed to parse the 'x-forwarded-for' header ip address. {e}");
            request_addr.ip()
        }
    }
}

async fn query_to_response(query: Vec<u8>, dns_socket: &mut DnsSocket, client_ip: IpAddr) -> Response<Body> {
    let reply = dns_socket.query_me_recursively(&query, Some(client_ip)).await;
    let lowest_ttl = get_lowest_ttl(&reply);

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::CONTENT_LENGTH, reply.len())
        .header(header::CACHE_CONTROL, format!("max-age={lowest_ttl}"))
        .body(Body::from(reply))
        .unwrap();

    response
}

async fn dns_query_get(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let client_ip = extract_client_ip(&client_addr, &headers);
    if let Err(response) = validate_accept_header(&headers) {
        return Err(response);
    }

    if let None = params.get("dns") {
        return Err((StatusCode::BAD_REQUEST, format!("valid dns query param required")));
    }
    let result = decode_dns_base64_packet(params.get("dns").unwrap());
    if let Err(e) = result {
        return Err(e);
    }
    let packet_bytes = result.unwrap();
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
    if let Err(response) = validate_accept_header(&headers) {
        return Err(response);
    }

    let body_result = axum::body::to_bytes(request.into_body(), 65535usize).await;
    if let Err(e) = body_result {
        return Err((StatusCode::BAD_REQUEST, e.to_string()));
    }

    let packet_bytes: Vec<u8> = body_result.unwrap().into();
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

    let app = Router::new()
        .route("/dns-query", get(dns_query_get))
        .route("/dns-query", post(dns_query_post))
        .layer(cors)
        .with_state(Arc::new(AppState { socket: dns_socket }));
    app
}

pub async fn run_doh_server(addr: SocketAddr, dns_socket: DnsSocket) {
    let app = create_app(dns_socket);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
}

#[cfg(test)]
mod tests {
    use crate::{dns_over_https::server::create_app, resolution::DnsSocket};
    use axum_test::TestServer;
    use simple_dns::{Name, Packet, Question};

    #[tokio::test]
    async fn query_doh_wireformat_get() {
        // RFC8484 example https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        let socket = DnsSocket::default().await.unwrap();
        socket.start_receive_loop();
        let app = create_app(socket);
        let server = TestServer::new(app).unwrap();
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
            "151"
        );

        let reply_bytes = response.into_bytes();
        let packet = Packet::parse(&reply_bytes).expect("Should be valid packet");
        assert_eq!(packet.name_servers.len(), 1)
    }

    #[tokio::test]
    async fn query_doh_wireformat_post() {
        // RFC8484 example https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        let socket = DnsSocket::default().await.unwrap();
        socket.start_receive_loop();
        let app = create_app(socket);
        let server = TestServer::new(app).unwrap();

        let mut query = Packet::new_query(50);
        let question = Question::new(
            Name::new_unchecked("example.com"),
            simple_dns::QTYPE::TYPE(simple_dns::TYPE::A),
            simple_dns::QCLASS::CLASS(simple_dns::CLASS::IN),
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
        assert_eq!(
            response
                .maybe_header("content-length")
                .expect("content-length available"),
            "46"
        );

        let reply_bytes = response.into_bytes();
        let packet = Packet::parse(&reply_bytes).expect("Should be valid packet");
        assert_eq!(packet.answers.len(), 1)
    }

    #[tokio::test]
    async fn wrong_content_type() {
        // RFC8484 example https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        let socket = DnsSocket::default().await.unwrap();
        socket.start_receive_loop();
        let app = create_app(socket);
        let server = TestServer::new(app).unwrap();
        let base64 = "AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJlbC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1zdGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ";
        let response = server
            .get("/dns-query")
            .add_query_param("dns", base64)
            .add_header("accept", "application/wrong_type")
            .await;

        response.assert_status_bad_request();
    }

    #[tokio::test]
    async fn e2e_test() {
        // RFC8484 example https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        // let socket = DnsSocket::default().await.unwrap();
        // socket.start_receive_loop();
        // run_doh_server("127.0.0.1:3000".parse().unwrap(), socket).await;

        let client = dnsoverhttps::Client::from_url("http://127.0.0.1:3000/dns-query").unwrap();
        let res = client.resolve_host("example.com").unwrap();
        assert_eq!(res.len(), 2);
        println!("Result IPs: {res:?}");
    }
}
