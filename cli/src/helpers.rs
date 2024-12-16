use pkarr::{PkarrClient, PkarrClientBuilder};


/// Construct new pkarr client with no cache, no resolver, only DHT
pub fn construct_pkarr_client() -> PkarrClient  {
    PkarrClientBuilder::default()
    // .maximum_ttl(0)
    .resolvers(None)
    .build().unwrap()
}