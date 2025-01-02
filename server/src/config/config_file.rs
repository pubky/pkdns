use anyhow::anyhow;
use dirs::home_dir;

use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::SocketAddr,
    num::NonZeroU64,
    path::{Path, PathBuf},
};


#[derive(Debug, Deserialize, Serialize)]
pub struct PkdnsConfig {
    pub general: General,
    pub dns: Dns,
    pub dht: Dht,
}

impl Default for PkdnsConfig {
    fn default() -> Self {
        Self {
            general: General::default(),
            dns: Dns::default(),
            dht: Dht::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct General {
    #[serde(default = "default_socket")]
    pub socket: SocketAddr,
    #[serde(default = "default_forward")]
    pub forward: SocketAddr,
    #[serde(default = "default_false")]
    pub verbose: bool,
    #[serde(default = "default_none")]
    pub dns_over_http_socket: Option<SocketAddr>,
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

// fn default_true() -> bool {
//     false
// }

#[derive(Debug, Deserialize, Serialize)]
pub struct Dns {
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u64,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u64,
    #[serde(default = "default_query_rate_limit")]
    pub query_rate_limit: u32,
    #[serde(default = "default_query_rate_limit_burst")]
    pub query_rate_limit_burst: u32,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            min_ttl: default_min_ttl(),
            max_ttl: default_max_ttl(),
            query_rate_limit: default_query_rate_limit(),
            query_rate_limit_burst: default_query_rate_limit_burst(),
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Dht {
    #[serde(default = "default_cache_mb")]
    pub cache_mb: NonZeroU64,
    #[serde(default = "default_dht_rate_limit")]
    pub dht_query_rate_limit: u32,
    #[serde(default = "default_dht_rate_limit_burst")]
    pub dht_query_rate_limit_burst: u32,
}

fn default_cache_mb() -> NonZeroU64 {
    NonZeroU64::new(100).unwrap()
}

fn default_dht_rate_limit() -> u32 {
    5
}

fn default_dht_rate_limit_burst() -> u32 {
    25
}

impl Default for Dht {
    fn default() -> Self {
        Self {
            cache_mb: default_cache_mb(),
            dht_query_rate_limit: default_dht_rate_limit(),
            dht_query_rate_limit_burst: default_dht_rate_limit_burst(),
        }
    }
}

/// Read the pkdns config file.
pub fn read_config(path: &Path) -> Result<PkdnsConfig, anyhow::Error> {
    let config_str = fs::read_to_string(path)?;
    let config: PkdnsConfig = toml::from_str(&config_str)?;

    Ok(config)
}

/// Read or create a config file at a given path.
pub fn read_or_create_config(path: &str) -> Result<PkdnsConfig, anyhow::Error> {
    let path = expand_tilde(path);
    let config = read_config(path.as_path());
    if config.is_ok() {
        return config;
    };

    let err = config.unwrap_err();
    tracing::debug!("Failed to read pkdns config file at {}. {err}", path.display());
    tracing::info!("Create a new config file from scratch {}.", path.display());

    let config = PkdnsConfig::default();
    let full_config = toml::to_string(&config).expect("Valid toml config.");
    let commented_out: Vec<String> = full_config.split("\n").map(|line| {
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
    }).collect();
    let commented_out = commented_out.join("\n");

    let content =
        format!("# PKDNS configuration file\n# More information on https://github.com/pubky/pkdns/server/sample-config.toml\n\n{commented_out}");
    fs::write(path, content).expect("Failed to write config file");
    Ok(config)
}

/// Reads the config from the directory or if it doesn't exist, creates a new config in the directory.
pub fn read_or_create_from_dir(dir_path: &str) -> Result<PkdnsConfig, anyhow::Error> {
    let mut path = expand_tilde(dir_path);
    if !path.exists() {
        if let Err(e) = fs::create_dir(path.clone()) {
            return Err(anyhow!(
                "Failed to create pkdns_dir path {}. {e}",
                path.display()
            ));
        };
    };
    if !path.is_dir() {
        return Err(anyhow!("pkdns_dir {} is not a directory.", path.display()));
    };
    path.push("pkdns.toml");

    read_or_create_config(path.to_str().expect("Valid path string"))
}

/// Expands the ~ to the users home directory
pub fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~") {
        if let Some(home) = home_dir() {
            let joined = home.join(&path[2..]);
            return joined;
        }
    }
    PathBuf::from(path)
}


#[cfg(test)]
mod tests {
    use super::*;


    #[tokio::test]
    async fn generate_sample_config() {
        // println!("{}", PkdnsConfig::commented_toml());
    }
}
