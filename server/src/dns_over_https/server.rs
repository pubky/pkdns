use axum::{body::Body, extract::{Query, State}, http::{header, HeaderMap, Response, StatusCode}, response::IntoResponse, routing::get, Router
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use simple_dns::Packet;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::resolution::DnsSocket;

/// RFC8484 Dns-over-http wireformat
/// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1

fn validate_accept_header(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    if let None = headers.get("accept") {
        return Err((StatusCode::BAD_REQUEST, format!("valid accept header required")));
    };
    let value = headers.get("accept").unwrap();
    if let Err(e) = value.to_str() {
        return Err((StatusCode::BAD_REQUEST, format!("valid accept header required")));
    }
    let value = value.to_str().unwrap();
    if value != "application/dns-message" {
        return Err((StatusCode::BAD_REQUEST, format!("valid accept header required")));
    }
    Ok(())
}

fn decode_dns_base64_packet(param: &String) -> Result<Vec<u8>, (StatusCode, String)> {
    let val = URL_SAFE_NO_PAD.decode(param);
    if let Err(e) = val {
        return Err((StatusCode::BAD_REQUEST, format!("Error decoding the dns base64 query parameter. {e}")));
    };
    let vec = val.unwrap();
    if let Err(e) = Packet::parse(&vec) {
        tracing::info!("{e}");
        return Err((StatusCode::BAD_REQUEST, format!("Failed to parse the base64 as a valid dns packet. {e}")));
    }
    Ok(vec)
}


async fn dns_query(
    headers: HeaderMap, 
    Query(params): Query<HashMap<String, String>>, 
    State(state): State<Arc<AppState>>
) -> Result<impl IntoResponse, impl IntoResponse> {
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
    let reply = socket.query_me(&packet_bytes, None).await;
    let response = Response::builder()
    .status(StatusCode::OK)
    .header(header::CONTENT_TYPE, "application/dns-message")
    .header(header::CONTENT_LENGTH, reply.len())
    .body(Body::from(reply)).unwrap();

    Ok(response)
    // Ok(StatusCode::OK)
}

pub struct AppState {
    pub socket: DnsSocket
}

fn create_app(dns_socket: DnsSocket) -> Router {
    let app = Router::new()
    .route("/dns-query", get(dns_query))
    .with_state(Arc::new(AppState{socket: dns_socket}));
    app
}

pub async fn run_doh_server(addr: SocketAddr, dns_socket: DnsSocket) {
    let app = create_app(dns_socket);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!("dns-over-http listening on http://{addr}/dns-query.");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use crate::{dns_over_https::server::create_app, resolution::DnsSocket};
    use axum_test::TestServer;
    use simple_dns::Packet;

    #[tokio::test]
    async fn query_doh_wireformat() {
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
        assert_eq!(response.maybe_header("content-type").expect("content-type available"), "application/dns-message");
        assert_eq!(response.maybe_header("content-length").expect("content-length available"), "151");

        let reply_bytes = response.into_bytes();
        let packet = Packet::parse(&reply_bytes).expect("Should be valid packet");
        assert_eq!(packet.name_servers.len(), 1)
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
}
