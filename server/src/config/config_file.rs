use anyhow::anyhow;
use dirs::home_dir;
use pkarr::dns::Name;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    fs,
    net::SocketAddr,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

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

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
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
        config
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

#[derive(Debug, Deserialize, Serialize, Clone)]
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
    pub top_level_domain: Option<String>,
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

fn default_top_level_domain() -> Option<String> {
    Some("key".to_string())
}

/// Consider an empty value "" as None
fn deserialize_top_level_domain<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize the input as an Option<String>
    let value = Option::<String>::deserialize(deserializer)?.filter(|val| !val.is_empty());

    if let Some(label) = &value {
        let name = match Name::new(label) {
            Ok(name) => name,
            Err(e) => return Err(D::Error::custom(e)),
        };
        if name.get_labels().len() != 1 {
            return Err(anyhow!("TLD can only be one label")).map_err(D::Error::custom);
        };
    }

    Ok(value)
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

/// Read the pkdns config file.
pub fn read_config(path: &Path) -> Result<ConfigToml, anyhow::Error> {
    let config_str = fs::read_to_string(path)?;
    let config: ConfigToml = toml::from_str(&config_str)?;

    Ok(config)
}

/// Read or create a config file at a given path.
pub fn read_or_create_config(path: &PathBuf) -> Result<ConfigToml, anyhow::Error> {
    let expanded_path = expand_tilde(path);

    let err = match read_config(expanded_path.as_path()) {
        Ok(config) => return Ok(config),
        Err(e) => e,
    };

    // Failed to read the config file.
    if expanded_path.exists() && expanded_path.is_file() {
        tracing::error!(
            "Unable to read configuration file at {}. {err}",
            expanded_path.display()
        );
        return Err(anyhow!("Failed to read {}. {err}", expanded_path.display()));
    }

    tracing::info!("Create a new config file from scratch {}.", expanded_path.display());
    let mut config = ConfigToml::default();
    // Add default values for Options. They don't appear otherwise in the commented out config.
    config.general.dns_over_http_socket = Some(
        "127.0.0.1:3000"
            .parse()
            .expect("127.0.0.1:3000 is a valid socket address"),
    );
    let full_config = toml::to_string(&config).expect("Valid toml config.");
    let commented_out: Vec<String> = full_config
        .split("\n")
        .map(|line| {
            if line.contains("[") {
                // Don't comment out sections.
                line.to_string()
            } else if line.is_empty() {
                // Don't comment out empty lines.
                line.to_string()
            } else {
                // Comment out regular lines
                format!("# {line}")
            }
        })
        .collect();
    let commented_out = commented_out.join("\n");

    let content =
        format!("# PKDNS configuration file\n# More information on https://github.com/pubky/pkdns/server/sample-config.toml\n\n{commented_out}");
    fs::write(expanded_path, content).expect("Failed to write config file");
    Ok(config)
}

/// Reads the config from the directory or if it doesn't exist, creates a new config in the directory.
pub fn read_or_create_from_dir(dir_path: &PathBuf) -> Result<ConfigToml, anyhow::Error> {
    let mut path = expand_tilde(dir_path);
    if !path.exists() {
        if let Err(e) = fs::create_dir(path.clone()) {
            return Err(anyhow!("Failed to create pkdns_dir path {}. {e}", path.display()));
        };
    };
    if !path.is_dir() {
        return Err(anyhow!("pkdns_dir {} is not a directory.", path.display()));
    };
    path.push("pkdns.toml");

    read_or_create_config(&path)
}

/// Expands the ~ to the users home directory
pub fn expand_tilde(path: &PathBuf) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = home_dir() {
            let without_home = path.strip_prefix("~/").expect("Invalid ~ prefix");
            let joined = home.join(without_home);
            return joined;
        }
    }
    PathBuf::from(path)
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
}