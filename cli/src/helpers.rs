use pkarr::{Client, Timestamp};

/// Construct new pkarr client with no cache, no resolver, only DHT
pub fn construct_pkarr_client() -> Client {
    let client = Client::builder().maximum_ttl(0).build().unwrap();
    client
}

// Turns a pkarr ntimestamp into a chrono timestamp
pub fn nts_to_chrono(ntc: Timestamp) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp((ntc.as_u64() / 1000000).try_into().unwrap(), 0).unwrap()
}
