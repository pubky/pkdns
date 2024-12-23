use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use simple_dns::Packet;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::resolution::DnsSocket;

fn validate_accept_header(headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    if let None = headers.get("accept") {
        return Err((StatusCode::BAD_REQUEST, "valid accept header required"));
    };
    let value = headers.get("accept").unwrap();
    if let Err(e) = value.to_str() {
        return Err((StatusCode::BAD_REQUEST, "valid accept header required"));
    }
    let value = value.to_str().unwrap();
    if value != "application/dns-message" {
        return Err((StatusCode::BAD_REQUEST, "valid accept header required"));
    }
    Ok(())
}

fn decode_dns_base64_packet(param: &String) -> Result<Vec<u8>, (StatusCode, &'static str)> {
    let val = URL_SAFE.decode(param);
    if let Err(e) = val {
        return Err((StatusCode::BAD_REQUEST, "Error decoding the dns base64 query parameter."));
    };
    let vec = val.unwrap();
    if let Err(e) = Packet::parse(&vec) {
        return Err((StatusCode::BAD_REQUEST, "Failed to parse the base64 as a valid dns packet."));
    }
    Ok(vec)
}


async fn dns_query(headers: HeaderMap, Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    if let Err(response) = validate_accept_header(&headers) {
        return response;
    }
    if let None = params.get("dns") {
        return (StatusCode::BAD_REQUEST, "valid dns query param required");
    }
    let result = decode_dns_base64_packet(params.get("dns").unwrap());
    if let Err(e) = result {
        return e;
    }
    let packet_bytes = result.unwrap();


    (StatusCode::OK, "ok")
}

struct AppState {
    // socket: DnsSocket
}

fn create_app() -> Router {
    let app = Router::new()
    .route("/dns-query", get(dns_query))
    .with_state(Arc::new(AppState{}));
    app
}

pub async fn run_doh_server(addr: SocketAddr) {
    let app = create_app();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!("dns-over-http listening on http://{addr}/dns-query.");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use crate::dns_over_https::server::create_app;
    use axum_test::TestServer;

    #[tokio::test]
    async fn query_doh_wireformat() {
        // RFC8484 example https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        let app = create_app();
        let server = TestServer::new(app).unwrap();
        let base64 = "AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJlbC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1zdGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ";
        let response = server
            .get("/dns-query")
            .add_query_param("dns", base64)
            .add_header("accept", "application/dns-message")
            .await;

        response.assert_status_ok();
        response.assert_text("ok");
    }

    #[tokio::test]
    async fn wrong_content_type() {
        // RFC8484 example https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        let app = create_app();
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
