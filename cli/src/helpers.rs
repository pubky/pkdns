use pkarr::Client;

/// Construct new pkarr client with no cache, no resolver, only DHT
pub fn construct_pkarr_client() -> Client {
    let client = Client::builder().no_relays().maximum_ttl(0).build().unwrap();
    client
}
