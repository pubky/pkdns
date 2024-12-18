use std::{
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    sync::Arc,
};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter as GovenerRateLimiter};

/**
 * Custom rate limiting key. A device usually gets
 * either one IPv4 address OR a /64 bit IPv6 address.
 * To prevent IPv6 abuse, RateLimitingKey only uses the first 64 bits.
 */
#[derive(Clone, Debug, Eq, PartialEq)]
enum RateLimitingKey {
    Ipv4(Ipv4Addr),
    IpV6 { significant_bits: u64 },
}

impl RateLimitingKey {
    /**
     * Generate a key from an IPv4 address.
     */
    pub fn from_ipv4(ip: Ipv4Addr) -> Self {
        Self::Ipv4(ip)
    }

    /**
     * Generate a key from an IPv6 address.
     */
    pub fn from_ipv6(ip: Ipv6Addr) -> Self {
        let segments = ip.segments();
        let key = ((segments[0] as u64) << 48)
            | ((segments[1] as u64) << 32)
            | ((segments[2] as u64) << 16)
            | (segments[3] as u64);
        return Self::IpV6 { significant_bits: key };
    }
}

impl From<IpAddr> for RateLimitingKey {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(val) => Self::from_ipv4(val),
            IpAddr::V6(val) => Self::from_ipv6(val),
        }
    }
}

impl Hash for RateLimitingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            RateLimitingKey::Ipv4(ipv4_addr) => {
                (0 as u8).hash(state); // IPv4 indicator to prevent overlap with the Ipv6 space.
                ipv4_addr.hash(state);
            }
            RateLimitingKey::IpV6 { significant_bits } => {
                (1 as u8).hash(state); // IPv6 indicator to prevent overlap with the Ipv4 space.
                significant_bits.hash(state);
            }
        }
    }
}

pub struct RateLimiterBuilder {
    max_per_second: Option<NonZeroU32>,
    max_per_minute: Option<NonZeroU32>,
    burst_size: Option<NonZeroU32>,
}

impl RateLimiterBuilder {
    pub fn new() -> Self {
        Self {
            max_per_second: None,
            max_per_minute: None,
            burst_size: None,
        }
    }

    /// Maximum number of request per second. Think of a bucket that gets filled with drops.
    /// This is the rate at which the bucket is emptied.
    /// Either seconds or minutes is allowed. Setting both is invalid.
    pub fn max_per_second(mut self, limit: Option<NonZeroU32>) -> Self {
        self.max_per_second = limit;
        self
    }

    /// Maximum number of request per minute. Think of a bucket that gets filled with drops.
    /// This is the rate at which the bucket is emptied.
    /// Either seconds or minutes is allowed. Setting both is invalid.
    pub fn max_per_minute(mut self, limit: Option<NonZeroU32>) -> Self {
        self.max_per_minute = limit;
        self
    }

    /// Burst size of requests a minute. Think of it as the bucket size.
    pub fn burst_size(mut self, size: Option<NonZeroU32>) -> Self {
        self.burst_size = size;
        self
    }

    /// Builds the RateLimiter. Panics if max_per_minute AND max_per_second is set at the same time.
    pub fn build(self) -> RateLimiter {
        if self.max_per_minute.is_some() && self.max_per_second.is_some() {
            panic!("Can't set max_per_minute and max_per_second at the same time.")
        };

        let mut quota: Quota;
        if let Some(limit) = self.max_per_minute {
            quota = Quota::per_minute(limit);
        } else if let Some(limit) = self.max_per_second {
            quota = Quota::per_second(limit);
        } else {
            return RateLimiter { limiter: None };
        }
        if let Some(size) = self.burst_size {
            quota = quota.allow_burst(size);
        }

        RateLimiter {
            limiter: Some(GovenerRateLimiter::keyed(quota)),
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    limiter: Option<DefaultKeyedRateLimiter<RateLimitingKey>>,
}

impl RateLimiter {
    /**
     * Checks if this IP address is limited. Increases the usage by one.
     */
    pub fn check_is_limited_and_increase(&self, ip: IpAddr) -> bool {
        if let Some(limiter) = &self.limiter {
            let is_rate_limited = limiter.check_key(&ip.into()).is_err();
            return is_rate_limited;
        };
        return false;
    }
}
