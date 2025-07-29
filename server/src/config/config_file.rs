use serde::{Deserialize, Deserializer, Serialize};
use std::{fs, net::SocketAddr, num::NonZeroU64, path::Path};

use crate::config::TopLevelDomain;

/// Error that can occur when reading a configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigReadError {
    /// The file did not exist or could not be read.
    #[error("config file not found: {0}")]
    NotFound(#[from] std::io::Error),
    /// The TOML was syntactically invalid.
    #[error("config file is not valid TOML: {0}")]
    NotValid(#[from] toml::de::Error),
}

/// Example configuration file
pub const SAMPLE_CONFIG: &str = include_str!("../../config.sample.toml");

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ConfigToml {
    #[serde(default)]
    pub general: General,
    #[serde(default)]
    pub dns: Dns,
    #[serde(default)]
    pub dht: Dht,
}

impl ConfigToml {
    /// Example configuration file as a string.
    pub fn sample() -> String {
        SAMPLE_CONFIG.to_string()
    }

    /// Render the embedded sample config but comment out every value,
    /// producing a handy template for end-users.
    pub fn commented_out_sample() -> String {
        SAMPLE_CONFIG
            .lines()
            .map(|line| {
                let trimmed = line.trim_start();
                let is_comment = trimmed.starts_with('#');
                if !is_comment && !trimmed.is_empty() {
                    format!("# {}", line)
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Read and parse a configuration file.
    ///
    /// # Arguments
    /// * `path` - The path to the TOML configuration file
    ///
    /// # Returns
    /// * `Result<ConfigToml>` - The parsed configuration or an error if reading/parsing fails
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigReadError> {
        let raw = fs::read_to_string(path)?;
        let config: ConfigToml = toml::from_str(&raw)?;
        Ok(config)
    }

    #[cfg(test)]
    pub fn test() -> Self {
        let mut config = Self::default();
        config.general.dns_over_http_socket = None;
        config.general.socket = "0.0.0.0:0".parse().expect("Is always be a valid socket address");
        config
    }
}

impl TryFrom<&str> for ConfigToml {
    type Error = ConfigReadError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let config: ConfigToml = toml::from_str(value)?;
        Ok(config)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct General {
    #[serde(default = "default_socket")]
    pub socket: SocketAddr,

    #[serde(default = "default_forward")]
    pub forward: SocketAddr,

    #[serde(default = "default_none")]
    pub dns_over_http_socket: Option<SocketAddr>,

    #[serde(default = "default_false")]
    pub verbose: bool,
}

impl Default for General {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            forward: default_forward(),
            verbose: default_false(),
            dns_over_http_socket: default_none(),
        }
    }
}

fn default_socket() -> SocketAddr {
    "0.0.0.0:53".parse().unwrap()
}

fn default_forward() -> SocketAddr {
    "8.8.8.8:53".parse().unwrap()
}

fn default_false() -> bool {
    false
}

fn default_none() -> Option<SocketAddr> {
    None
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Dns {
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u64,

    #[serde(default = "default_max_ttl")]
    pub max_ttl: u64,

    #[serde(default = "default_query_rate_limit")]
    pub query_rate_limit: u32,

    #[serde(default = "default_query_rate_limit_burst")]
    pub query_rate_limit_burst: u32,

    #[serde(default = "default_false")]
    pub disable_any_queries: bool,

    #[serde(default = "default_icann_cache_mb")]
    pub icann_cache_mb: u64,

    #[serde(default = "default_max_recursion_depth")]
    pub max_recursion_depth: u8,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            min_ttl: default_min_ttl(),
            max_ttl: default_max_ttl(),
            query_rate_limit: default_query_rate_limit(),
            query_rate_limit_burst: default_query_rate_limit_burst(),
            disable_any_queries: default_false(),
            icann_cache_mb: default_icann_cache_mb(),
            max_recursion_depth: default_max_recursion_depth(),
        }
    }
}

fn default_min_ttl() -> u64 {
    60
}

fn default_max_ttl() -> u64 {
    86400
}

fn default_query_rate_limit() -> u32 {
    100
}

fn default_query_rate_limit_burst() -> u32 {
    200
}

fn default_icann_cache_mb() -> u64 {
    100
}

fn default_max_recursion_depth() -> u8 {
    15
}

#[derive(Debug, Deserialize, Clone)]
pub struct Dht {
    #[serde(default = "default_cache_mb")]
    pub dht_cache_mb: NonZeroU64,
    #[serde(default = "default_dht_rate_limit")]
    pub dht_query_rate_limit: u32,
    #[serde(default = "default_dht_rate_limit_burst")]
    pub dht_query_rate_limit_burst: u32,
    #[serde(
        default = "default_top_level_domain",
        deserialize_with = "deserialize_top_level_domain"
    )]
    pub top_level_domain: Option<TopLevelDomain>,
}

fn deserialize_top_level_domain<'de, D>(deserializer: D) -> Result<Option<TopLevelDomain>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(tld) = &value {
        if tld.is_empty() {
            return Ok(None);
        }
    }
    Ok(value.map(TopLevelDomain::new))
}

fn default_cache_mb() -> NonZeroU64 {
    NonZeroU64::new(100).expect("100 is a valid non-zero u64")
}

fn default_dht_rate_limit() -> u32 {
    5
}

fn default_dht_rate_limit_burst() -> u32 {
    25
}

fn default_top_level_domain() -> Option<TopLevelDomain> {
    Some(TopLevelDomain::new("key".to_string()))
}

impl Default for Dht {
    fn default() -> Self {
        Self {
            dht_cache_mb: default_cache_mb(),
            dht_query_rate_limit: default_dht_rate_limit(),
            dht_query_rate_limit_burst: default_dht_rate_limit_burst(),
            top_level_domain: default_top_level_domain(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sample_config() {
        let _: ConfigToml = toml::from_str(SAMPLE_CONFIG).expect("Sample config must be parseble");
    }

    #[test]
    fn test_commented_out_sample() {
        let commented_out = ConfigToml::commented_out_sample();
        println!("{commented_out}");
    }

    #[test]
    fn test_default_config_top_level_domain() {
        let config_str = "[dht]\ntop_level_domain = \"\"";
        let config = ConfigToml::try_from(config_str).unwrap();
        assert!(config.dht.top_level_domain.is_none());

        let config_str = "[dht]\ntop_level_domain = \"test\"";
        let config = ConfigToml::try_from(config_str).unwrap();
        assert_eq!(config.dht.top_level_domain.unwrap().0, "test".to_string());
    }
}
