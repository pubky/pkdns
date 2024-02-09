use std::{sync::Arc, time::Duration};

use pkarr::{dns::Packet, PublicKey};

use tokio::sync::Mutex;
use ttl_cache::TtlCache;

/**
 * Pkarr record ttl cache
 */
#[derive(Clone)]
pub struct PkarrPacketTtlCache {
    max_cache_ttl: u64,
    cache: Arc<Mutex<TtlCache<String, Vec<u8>>>>
}

impl PkarrPacketTtlCache {
    pub async fn new(max_cache_ttl: u64) -> Self {
        PkarrPacketTtlCache {
            max_cache_ttl,
            cache: Arc::new(Mutex::new(TtlCache::new(100_000)))
        }
    }

    /**
     * Adds packet and caches it for the ttl the least long lived answer is valid for.
     */
    pub async fn add(&mut self, pubkey: PublicKey, reply: Vec<u8>) {
        let default_ttl = 1200;
        let packet = Packet::parse(&reply).unwrap();
        let min_ttl = packet
            .answers
            .iter()
            .map(|answer| answer.ttl)
            .min()
            .unwrap_or(default_ttl) as u64;

        let ttl = 60.max(min_ttl); // At least 1min
        let ttl = ttl.min(self.max_cache_ttl);
        let ttl = Duration::from_secs(ttl as u64);

        let mut cache = self.cache.lock().await;
        cache.insert(pubkey.to_z32(), reply, ttl);
    }

    /**
     * Get packet
     */
    pub async fn get(&self, pubkey: &PublicKey) -> Option<Vec<u8>> {
        let z32 = pubkey.to_z32();
        let cache = self.cache.lock().await;
        cache.get(&z32).map(|value| value.clone())
    }
}
