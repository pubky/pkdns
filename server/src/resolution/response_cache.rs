use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use moka::{future::Cache, policy::EvictionPolicy};
use pkarr::dns::Packet;

/// Caches dns responses.
#[derive(Clone, Debug)]
pub struct CacheItem {
    pub query_key: String,
    pub response: Vec<u8>,
    created_at: SystemTime,
}

impl CacheItem {
    pub fn new(query: Vec<u8>, response: Vec<u8>) -> Result<Self, anyhow::Error> {
        let packet = Packet::parse(&response)?;
        let _ = Packet::parse(&response)?; // Validate that the response is parseable.
        Ok(Self {
            query_key: Self::derive_query_key(&query)?,
            response,
            created_at: SystemTime::now(),
        })
    }

    /// Derives a query key from the first question. May fail if the packet cant be parsed
    /// or the query doesn't have a question.
    pub fn derive_query_key(query: &[u8]) -> Result<String, anyhow::Error> {
        let packet = Packet::parse(query)?;
        let question = packet
            .questions
            .first()
            .ok_or(anyhow!("Query does not include a question."))?;
        Ok(format!("{}:{:?}:{:?}", question.qname, question.qclass, question.qtype))
    }

    fn response_packet(&self) -> Packet {
        Packet::parse(&self.response).unwrap()
    }

    /// Lowest ttl of any anwser in seconds. Used to determine when to update the cache.
    /// NotFound or packet with now answeres => None.
    pub fn lowest_answer_ttl(&self) -> Option<u64> {
        self.response_packet()
            .answers
            .iter()
            .map(|answer| answer.ttl as u64)
            .min()
    }

    /// Size of the cached value in the memory.
    /// Approximation. Could be done better.
    pub fn memory_size(&self) -> usize {
        self.query_key.len() + self.response.len() + 11
    }

    /// When this cached item expires.
    pub fn expires_in(&self, min_ttl: u64, max_ttl: u64) -> SystemTime {
        let ttl = self.lowest_answer_ttl().unwrap_or(min_ttl);
        let ttl = if ttl < min_ttl { min_ttl } else { ttl };
        let ttl = if ttl > max_ttl { max_ttl } else { ttl };
        self.created_at
            .checked_add(Duration::from_secs(ttl))
            .expect("Valid time because ttl is bound")
    }

    /// If this cached item is outdated (expired ttl).
    pub fn is_outdated(&self, min_ttl: u64, max_ttl: u64) -> bool {
        self.expires_in(min_ttl, max_ttl) < SystemTime::now()
    }
}

/**
 * LRU cache for ICANN responses.
 */
#[derive(Clone, Debug)]
pub struct IcannLruCache {
    cache: Cache<String, CacheItem>, // Moka Cache is thread safe
    min_ttl: u64,
    max_ttl: u64,
}

impl IcannLruCache {
    pub fn new(cache_size_mb: u64, min_ttl: u64, max_ttl: u64) -> Self {
        IcannLruCache {
            cache: Cache::builder()
                .weigher(|_key, value: &CacheItem| -> u32 { value.memory_size() as u32 })
                .max_capacity(cache_size_mb * 1024 * 1024)
                .build(),
            max_ttl,
            min_ttl,
        }
    }

    /// Adds a new item to the cache.
    pub async fn add(&mut self, query: Vec<u8>, response: Vec<u8>) -> Result<(), anyhow::Error> {
        let item = CacheItem::new(query, response)?;
        self.cache.insert(item.query_key.clone(), item).await;
        Ok(())
    }

    /// Get cached packet by query. Fails if the query can't per parsed.
    pub async fn get(&self, query: &[u8]) -> Result<Option<CacheItem>, anyhow::Error> {
        let key = CacheItem::derive_query_key(query)?;
        let value = self.cache.get(&key).await;
        if let Some(item) = &value {
            if item.is_outdated(self.min_ttl, self.max_ttl) {
                return Ok(None);
            };
        };

        Ok(value)
    }

    /// Approximated size of the cache in bytes. May not be 100% accurate due to pending counts.
    #[allow(dead_code)]
    pub fn approx_size_bytes(&self) -> u64 {
        self.cache.weighted_size()
    }

    #[allow(dead_code)]
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkarr::dns::{rdata::A, Name, Question, ResourceRecord};

    fn example_query_response(ttl: u32) -> (Vec<u8>, Vec<u8>) {
        let mut query_packet = Packet::new_query(0);
        let question = Question::new(
            Name::new("example.com").unwrap(),
            pkarr::dns::QTYPE::ANY,
            pkarr::dns::QCLASS::ANY,
            false,
        );

        query_packet.questions.push(question);
        let query = query_packet.build_bytes_vec().unwrap();

        let mut response_packet = Packet::new_reply(0);
        let answer = ResourceRecord::new(
            Name::new("example.com").unwrap(),
            pkarr::dns::CLASS::IN,
            ttl,
            pkarr::dns::rdata::RData::A(A { address: 32 }),
        );
        response_packet.answers.push(answer);

        let response = response_packet.build_bytes_vec().unwrap();
        (query, response)
    }

    #[tokio::test]
    async fn add_and_get() {
        let mut cache = IcannLruCache::new(1, 0, 99999);
        let (query, response) = example_query_response(60);
        cache.add(query.clone(), response.clone()).await.unwrap();

        let cache_option = cache.get(&query).await.expect("Previously cached item");
        let res = cache_option.unwrap();
        assert_eq!(res.response, response);
    }

    #[tokio::test]
    async fn outdated_get() {
        let mut cache = IcannLruCache::new(1, 0, 99999);
        let (query, response) = example_query_response(0);
        cache.add(query.clone(), response.clone()).await.unwrap();

        let cache_option = cache.get(&query).await.expect("Previously cached item");
        assert!(cache_option.is_none());
    }

    #[tokio::test]
    async fn zero_cache_size() {
        let mut cache = IcannLruCache::new(0, 0, 99999);
        let (query, response) = example_query_response(60);
        cache.add(query.clone(), response.clone()).await.unwrap();

        let cache_option = cache.get(&query).await.expect("Previously cached item");
        assert!(cache_option.is_none());
    }
}
