use std::{time::{SystemTime, UNIX_EPOCH}};


use moka::future::Cache;
use pkarr::{PublicKey, SignedPacket};


/**
 * Goal1: Cache things as long as possible to make any attack on the DHT unfeasible.
 * Goal2: Prevent attackers from overflowing the cache and evict values this way.
 */




const DEFAULT_MIN_TTL: u64 = 60;

/**
 * Signed Packet that's cached.
 */
#[derive(Clone, Debug)]
pub struct CachedSignedPacket {
    pub packet: SignedPacket,
    /**
     * When the packet got added to the cache. Seconds timestamp since UNIX_EPOCH.
     */
    pub cached_at: u64
}

impl CachedSignedPacket {
    pub fn new(packet: SignedPacket) -> Self {
        let start = SystemTime::now();
        let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

        Self {
            packet,
            cached_at: since_the_epoch.as_secs() as u64
        }
    }

    /**
     * Lowest ttl of any anwser in seconds. Used to determine when to update the cache.
     */
    pub fn lowest_answer_ttl(&self) -> Option<u64> {
         self.packet.packet().answers.iter().map(|answer| answer.ttl as u64).min()
    }

    pub fn public_key(&self) -> PublicKey {
        self.packet.public_key()
    }

    /**
     * Size of the cached value in the memory.
     */
    pub fn memory_size(&self) -> usize {
        self.packet.as_bytes().len() // Not 100% correct because it missed the other values in this struct. Close enough though.
    }

    /**
     * If this value is outdated and should be refreshed
     */
    pub fn is_ttl_expired(&self) -> bool {
        self.ttl_expires_in_s() == 0
    }

    /**
     * When the smallest ttl expires in seconds.
     */
    pub fn ttl_expires_in_s(&self) -> u64 {
        let min_ttl = self.lowest_answer_ttl().map(|val| {
            if val < DEFAULT_MIN_TTL {
                DEFAULT_MIN_TTL
            } else {
                val
            }
        }).unwrap_or(DEFAULT_MIN_TTL);

        let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

        let age_seconds = now - self.cached_at;
        if age_seconds > min_ttl {
            0
        } else {
            min_ttl - age_seconds
        }
    }

}


/**
 * Pkarr record LRU cache.
 */
#[derive(Clone, Debug)]
pub struct PkarrPacketLruCache {
    cache: Cache<PublicKey, CachedSignedPacket>
}

impl PkarrPacketLruCache {
    pub fn new(cache_size_mb: Option<u64>) -> Self {
        let cache_size_mb = cache_size_mb.unwrap_or(100); // 100MB by default
        PkarrPacketLruCache {
            cache: Cache::builder()
            .weigher(|_key, value: &CachedSignedPacket| -> u32 {
               value.memory_size() as u32
            })
            .max_capacity(cache_size_mb * 1024*1024).build()
        }
    }

    /**
     * Adds packet and caches it for the ttl the least long lived answer is valid for.
     */
    pub async fn add(&mut self, packet: SignedPacket) -> CachedSignedPacket {
        if let Some(cached) = self.get(&packet.public_key()).await {
            let new_packet_is_older = cached.packet.timestamp() > packet.timestamp();
            if new_packet_is_older {
                // Existing packet is newer than already cached one. Don't update cache. Return existing one.
                return cached
            }
        };

        let element = CachedSignedPacket::new(packet);
        self.cache.insert(element.public_key(), element.clone()).await;
        element
    }

    /**
     * Get packet
     */
    pub async fn get(&self, pubkey: &PublicKey) -> Option<CachedSignedPacket> {
        let value = self.cache.get(pubkey).await;
        value
    }

    /**
     * Approximated size of the cache in bytes. May not be 100% accurate due to pending counts.
     */
    pub fn approx_size_bytes(&self) -> u64 {
        self.cache.weighted_size()
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}


#[cfg(test)]
mod tests {
    use pkarr::{dns::{Name, Packet, ResourceRecord}, Keypair, SignedPacket};

    use super::*;
    use std::net::Ipv4Addr;

    fn example_signed_packet() -> SignedPacket {
        let keypair = Keypair::random();
        // let uri = keypair.to_uri_string();
        // println!("Publish packet with pubkey {}", uri);

        let mut packet = Packet::new_reply(0);
        let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();
        let record = ResourceRecord::new(
            Name::new("pknames.p2p").unwrap(),
            pkarr::dns::CLASS::IN,
            100,
            pkarr::dns::rdata::RData::A(ip.try_into().unwrap()),
        );
        packet.answers.push(record);
        let record = ResourceRecord::new(
            Name::new(".").unwrap(),
            pkarr::dns::CLASS::IN,
            100,
            pkarr::dns::rdata::RData::A(ip.try_into().unwrap()),
        );
        packet.answers.push(record);
        SignedPacket::from_packet(&keypair, &packet).unwrap()
    }

    #[tokio::test]
    async fn packet_memory_size() {
        let packet = example_signed_packet();
        let cached = CachedSignedPacket::new(packet.clone());
        assert_eq!(cached.memory_size(), 212); 
    }

    #[tokio::test]
    async fn cache_size() {
        let mut cache = PkarrPacketLruCache::new(Some(1));
        assert_eq!(cache.approx_size_bytes(), 0);

        for _ in 0..10 {
            cache.add(example_signed_packet()).await;
        }
        cache.cache.run_pending_tasks().await;
        assert_eq!(cache.approx_size_bytes(), 2120);
    }

    #[tokio::test]
    async fn insert_get() {
        let mut cache = PkarrPacketLruCache::new(Some(1));
        let packet = example_signed_packet();
        cache.add(packet.clone()).await;

        for _ in 0..10 {
            cache.add(example_signed_packet()).await;
        };

        let recalled = cache.get(&packet.public_key()).await.expect("Value must be in cache");
        assert_eq!(recalled.public_key(), packet.public_key());
    }

}