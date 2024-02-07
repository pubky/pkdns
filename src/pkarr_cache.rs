use std::{sync::Arc, time::Duration};

use pkarr::{dns::Packet, PublicKey};
use retainer::Cache;
use tokio::{sync::Mutex, task::JoinHandle};


/**
 * Pkarr record ttl cache
 */
#[derive(Clone)]
pub struct PkarrPacketTtlCache {
    cache: Arc<Cache<String, Vec<u8>>>,
    max_cache_ttl: u64,
    monitor: Arc<Mutex<JoinHandle<()>>>
}

impl PkarrPacketTtlCache {
    pub async fn new(max_cache_ttl: u64) -> Self {
        let cache: Arc<Cache<String, Vec<u8>>> = Arc::new(Cache::new());
        let monitor = tokio::spawn(async move {
            cache.monitor(4, 0.25, Duration::from_secs(3)).await
        });
        let monitor = Arc::new(Mutex::new(monitor));
        PkarrPacketTtlCache {
            cache: Arc::new(Cache::new()),
            max_cache_ttl,
            monitor
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

        self.cache.insert(pubkey.to_z32(), reply, ttl).await;
    }

    pub async fn get(&self, pubkey: &PublicKey) -> Option<Vec<u8>> {
        let z32 = pubkey.to_z32();
        self.cache.get(&z32).await.map(|value| value.clone())
    }

    pub async fn stop(self) {
        self.monitor.lock().await.abort();
    }
}
