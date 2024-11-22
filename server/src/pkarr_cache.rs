use std::time::{SystemTime, UNIX_EPOCH};

use moka::future::Cache;
use pkarr::{PublicKey, SignedPacket};

/**
 * Goal1: Cache things as long as possible to make any attack on the DHT unfeasible.
 * Goal2: Prevent attackers from overflowing the cache and evict values this way.
 */

const DEFAULT_MIN_TTL: u64 = 60;

/**
 * Timestamp in seconds since UNIX_EPOCH
 */
fn get_timestamp_seconds() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    since_the_epoch.as_secs() as u64
}

/**
 * Caches pkarr packets and not found pkarr packets.
 * Not found is important to avoid calling the DHT over and over again.
 */
#[derive(Clone, Debug)]
pub enum CacheItem {
    NotFound {
        public_key: PublicKey,
        /**
         * When the packet got added to the cache or cache got updated. Seconds timestamp since UNIX_EPOCH.
         */
        cached_at: u64,
    },
    Packet {
        packet: SignedPacket,
        /**
         * When the packet got added to the cache or cache got updated. Seconds timestamp since UNIX_EPOCH.
         */
        cached_at: u64,
    },
}

impl CacheItem {
    pub fn new_packet(packet: SignedPacket) -> Self {
        Self::Packet {
            packet: packet,
            cached_at: get_timestamp_seconds(),
        }
    }

    pub fn new_not_found(pubkey: PublicKey) -> Self {
        Self::NotFound {
            public_key: pubkey,
            cached_at: get_timestamp_seconds(),
        }
    }

    pub fn is_not_found(&self) -> bool {
        if let CacheItem::NotFound {
            public_key: _,
            cached_at: _,
        } = self
        {
            true
        } else {
            false
        }
    }

    pub fn is_packet(&self) -> bool {
        if let CacheItem::Packet {
            packet: _,
            cached_at: _,
        } = self
        {
            true
        } else {
            false
        }
    }

    /**
     * Returns signed packet. Panics if not found.
     */
    pub fn unwrap(self) -> SignedPacket {
        if let CacheItem::Packet { packet, cached_at: _ } = self {
            return packet;
        } else {
            panic!("Can not unwrap CacheItem without a packet.")
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            CacheItem::NotFound {
                public_key,
                cached_at: _,
            } => public_key.clone(),
            CacheItem::Packet { packet, cached_at: _ } => packet.public_key(),
        }
    }

    /**
     * Updates the cached_at timestamp to now.
     */
    pub fn refresh_cached_at(&mut self) {
        match self {
            CacheItem::NotFound {
                public_key: _,
                cached_at,
            } => {
                *cached_at = get_timestamp_seconds();
            }
            CacheItem::Packet { packet: _, cached_at } => {
                *cached_at = get_timestamp_seconds();
            }
        }
    }

    /**
     * Timestamp given by the controller of the keypair. Basically a version number of the packet.
     * NotFound items always have a timestamp of 0.
     */
    pub fn controller_timestamp(&self) -> u64 {
        match self {
            CacheItem::NotFound {
                public_key: _,
                cached_at: _,
            } => 0,
            CacheItem::Packet { packet, cached_at: _ } => packet.timestamp(),
        }
    }

    fn cached_at(&self) -> u64 {
        match self {
            CacheItem::NotFound {
                public_key: _,
                cached_at,
            } => cached_at.clone(),
            CacheItem::Packet { packet: _, cached_at } => cached_at.clone(),
        }
    }

    /**
     * Lowest ttl of any anwser in seconds. Used to determine when to update the cache.
     * NotFound or packet with now answeres => None.
     */
    fn lowest_answer_ttl(&self) -> Option<u64> {
        match self {
            CacheItem::NotFound {
                public_key: _,
                cached_at: _,
            } => None,
            CacheItem::Packet { packet, cached_at: _ } => {
                packet.packet().answers.iter().map(|answer| answer.ttl as u64).min()
            }
        }
    }

    /**
     * Size of the cached value in the memory.
     */
    pub fn memory_size(&self) -> usize {
        match self {
            CacheItem::NotFound {
                public_key: _,
                cached_at: _,
            } => {
                32 + 8 // Public key 32 + cached_at 8
            }
            CacheItem::Packet { packet, cached_at: _ } => packet.as_bytes().len() + 8,
        }
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
        let min_ttl = self
            .lowest_answer_ttl()
            .map(|val| if val < DEFAULT_MIN_TTL { DEFAULT_MIN_TTL } else { val })
            .unwrap_or(DEFAULT_MIN_TTL);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let age_seconds = now - self.cached_at();
        if age_seconds > min_ttl {
            0
        } else {
            min_ttl - age_seconds
        }
    }
}

/**
 * LRU cache for packets.
 */
#[derive(Clone, Debug)]
pub struct PkarrPacketLruCache {
    cache: Cache<PublicKey, CacheItem>, // Moka Cache is thread safe
}

impl PkarrPacketLruCache {
    pub fn new(cache_size_mb: Option<u64>) -> Self {
        let cache_size_mb = cache_size_mb.unwrap_or(100); // 100MB by default
        PkarrPacketLruCache {
            cache: Cache::builder()
                .weigher(|_key, value: &CacheItem| -> u32 { value.memory_size() as u32 })
                .max_capacity(cache_size_mb * 1024 * 1024)
                .build(),
        }
    }

    /**
     * Adds a new item to the cache. Makes sure that older items do not override newer items.
     */
    async fn add(&mut self, new_item: CacheItem) -> CacheItem {
        if let Some(mut already_cached) = self.get(&new_item.public_key()).await {
            // Already in cache
            let same_age = new_item.controller_timestamp() == already_cached.controller_timestamp();
            if same_age {
                // Update cached_at timestamp
                already_cached.refresh_cached_at();
                self.cache
                    .insert(already_cached.public_key(), already_cached.clone())
                    .await;
                return already_cached;
            }

            let new_packet_is_older = new_item.controller_timestamp() < already_cached.controller_timestamp();
            if new_packet_is_older {
                // Existing packet is newer than already cached one. Don't update cache. Return existing one.
                return already_cached;
            }
        };

        self.cache.insert(new_item.public_key(), new_item.clone()).await;
        new_item
    }

    /**
     * Adds packet. Makes sure to not override newer instances in the cache.
     */
    pub async fn add_packet(&mut self, packet: SignedPacket) -> CacheItem {
        let new_item = CacheItem::new_packet(packet);
        self.add(new_item).await
    }

    /**
     * Adds not found. Makes sure to not override newer instances in the cache.
     */
    pub async fn add_not_found(&mut self, pubkey: PublicKey) -> CacheItem {
        let new_item = CacheItem::new_not_found(pubkey);
        self.add(new_item).await
    }

    /**
     * Get packet
     */
    pub async fn get(&self, pubkey: &PublicKey) -> Option<CacheItem> {
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
    use pkarr::{
        dns::{Name, Packet, ResourceRecord},
        Keypair, SignedPacket,
    };

    use super::*;
    use std::net::Ipv4Addr;

    fn example_signed_packet(keypair: Keypair) -> SignedPacket {
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
        let packet = example_signed_packet(Keypair::random());
        let cached = CacheItem::new_packet(packet.clone());
        assert_eq!(cached.memory_size(), 212);
    }

    #[tokio::test]
    async fn cache_size() {
        let mut cache = PkarrPacketLruCache::new(Some(1));
        assert_eq!(cache.approx_size_bytes(), 0);

        for _ in 0..10 {
            cache.add_packet(example_signed_packet(Keypair::random())).await;
        }
        cache.cache.run_pending_tasks().await;
        assert_eq!(cache.approx_size_bytes(), 2120);
    }

    #[tokio::test]
    async fn insert_get() {
        let mut cache = PkarrPacketLruCache::new(Some(1));
        let packet = example_signed_packet(Keypair::random());
        cache.add_packet(packet.clone()).await;

        for _ in 0..10 {
            cache.add_packet(example_signed_packet(Keypair::random())).await;
        }

        let recalled = cache.get(&packet.public_key()).await.expect("Value must be in cache");
        assert_eq!(recalled.public_key(), packet.public_key());
    }

    #[tokio::test]
    async fn override_old_cached_packet() {
        let mut cache = PkarrPacketLruCache::new(Some(1));
        let key = Keypair::random();
        let packet1 = example_signed_packet(key.clone());
        let packet2 = example_signed_packet(key.clone());
        assert_ne!(packet1.timestamp(), packet2.timestamp());

        cache.add_packet(packet1.clone()).await;
        cache.add_packet(packet2.clone()).await;
        let cached = cache.get(&key.public_key()).await.unwrap();
        assert_eq!(packet2.timestamp(), cached.controller_timestamp());
    }

    #[tokio::test]
    async fn keep_newer_cached_packet() {
        let mut cache = PkarrPacketLruCache::new(Some(1));
        let key = Keypair::random();
        let packet1 = example_signed_packet(key.clone());
        let packet2 = example_signed_packet(key.clone());
        assert_ne!(packet1.timestamp(), packet2.timestamp());

        cache.add_packet(packet2.clone()).await;
        cache.add_packet(packet1.clone()).await;
        let cached = cache.get(&key.public_key()).await.unwrap();
        assert_eq!(packet2.timestamp(), cached.controller_timestamp());
    }

    #[tokio::test]
    async fn override_old_not_found_cached_packet() {
        let mut cache = PkarrPacketLruCache::new(Some(1));
        let key = Keypair::random();
        let packet1 = example_signed_packet(key.clone());
        cache.add(CacheItem::new_not_found(key.public_key())).await;
        let cached = cache.get(&key.public_key()).await.unwrap();
        assert_eq!(cached.controller_timestamp(), 0);
        cache.add_packet(packet1.clone()).await;
        let cached = cache.get(&key.public_key()).await.unwrap();
        assert_eq!(packet1.timestamp(), cached.controller_timestamp());
    }

    #[tokio::test]
    async fn not_found_not_overriding_cached_packet() {
        let mut cache = PkarrPacketLruCache::new(Some(1));
        let key = Keypair::random();
        let packet1 = example_signed_packet(key.clone());
        cache.add_packet(packet1.clone()).await;
        cache.add(CacheItem::new_not_found(key.public_key())).await;
        let cached = cache.get(&key.public_key()).await.unwrap();
        assert_eq!(packet1.timestamp(), cached.controller_timestamp());
    }


}
