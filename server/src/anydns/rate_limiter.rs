use std::{
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32, sync::Arc,
};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter as GovenerRateLimiter};

/**
 * Custom rate limiting key. A device usually gets
 * either one IPv4 address OR a /64 bit IPv6 address.
 * To prevent IPv6 abuse, RateLimitingKey only uses the first 64 bits
 * of the IPv6 address to rate limit.
 */
#[derive(Clone, Debug, Eq, PartialEq)]
enum RateLimitingKey {
    Ipv4(Ipv4Addr),
    IpV6 { significant_bits: u64 },
}

impl RateLimitingKey {
    /**
     * Generates a key from a ip address.
     */
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(val) => Self::from_ipv4(val),
            IpAddr::V6(val) => Self::from_ipv6(val),
        }
    }

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

impl Hash for RateLimitingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            RateLimitingKey::Ipv4(ipv4_addr) => {
                ipv4_addr.hash(state);
                (0 as u8).hash(state); // IPv4 indicator to prevent overlap with the Ipv6 space.
            }
            RateLimitingKey::IpV6 { significant_bits } => {
                significant_bits.hash(state);
                (1 as u8).hash(state); // IPv6 indicator to prevent overlap with the Ipv6 space.
            }
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    limiter: Option<DefaultKeyedRateLimiter<RateLimitingKey>>,
}

impl RateLimiter {
    pub fn new(max_per_second: Option<NonZeroU32>) -> Self {
        Self {
            limiter: max_per_second.map(|limit| {
                let quota = Quota::per_second(limit);
                GovenerRateLimiter::keyed(quota)
            }),
        }
    }

    /**
     * Checks if this IP address is limited. Increases the usage by one.
     */
    pub fn check_is_limited_and_increase(&self, ip: IpAddr) -> bool {
        if let Some(limiter) = &self.limiter {
            let key = RateLimitingKey::from_ip(ip.clone());
            let is_rate_limited = limiter.check_key(&key).is_err();
            return is_rate_limited;
        };
        return false
    }
}
