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
        Self::IpV6 { significant_bits: key }
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
                0_u8.hash(state); // IPv4 indicator to prevent overlap with the Ipv6 space.
                ipv4_addr.hash(state);
            }
            RateLimitingKey::IpV6 { significant_bits } => {
                1_u8.hash(state); // IPv6 indicator to prevent overlap with the Ipv4 space.
                significant_bits.hash(state);
            }
        }
    }
}

pub struct RateLimiterBuilder {
    max_per_second: u32,
    max_per_minute: u32,
    burst_size: u32,
}

impl RateLimiterBuilder {
    pub fn new() -> Self {
        Self {
            max_per_second: 0,
            max_per_minute: 0,
            burst_size: 0,
        }
    }

    /// Maximum number of request per second. Think of a bucket that gets filled with drops.
    /// This is the rate at which the bucket is emptied.
    /// Either seconds or minutes is allowed. Setting both is invalid.
    /// 0 is disabled.
    pub fn max_per_second(mut self, limit: u32) -> Self {
        self.max_per_second = limit;
        self
    }

    /// Maximum number of request per minute. Think of a bucket that gets filled with drops.
    /// This is the rate at which the bucket is emptied.
    /// Either seconds or minutes is allowed. Setting both is invalid.
    /// 0 is disabled.
    pub fn max_per_minute(mut self, limit: u32) -> Self {
        self.max_per_minute = limit;
        self
    }

    /// Burst size of requests a minute. Think of it as the bucket size.
    /// 0 is disabled.
    pub fn burst_size(mut self, size: u32) -> Self {
        self.burst_size = size;
        self
    }

    /// Builds the RateLimiter. Panics if max_per_minute AND max_per_second is set at the same time.
    pub fn build(self) -> RateLimiter {
        if self.max_per_minute > 0 && self.max_per_second > 0 {
            panic!("Can't set max_per_minute and max_per_second at the same time.")
        };

        let mut quota: Quota;
        if self.max_per_minute > 0 {
            quota = Quota::per_minute(NonZeroU32::new(self.max_per_minute).expect("max_per_minute is always non-zero"));
        } else if self.max_per_second > 0 {
            quota = Quota::per_second(NonZeroU32::new(self.max_per_second).expect("max_per_second is always non-zero"));
        } else {
            return RateLimiter { limiter: None };
        }

        if self.burst_size > 0 {
            quota = quota.allow_burst(NonZeroU32::new(self.burst_size).expect("burst_size is always non-zero"));
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
    pub fn check_is_limited_and_increase(&self, ip: &IpAddr) -> bool {
        if let Some(limiter) = &self.limiter {
            let ip = *ip;
            let is_rate_limited = limiter.check_key(&ip.into()).is_err();
            return is_rate_limited;
        };
        false
    }
}
