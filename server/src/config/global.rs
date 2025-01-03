use once_cell::sync::Lazy;
use std::sync::RwLock;
use super::config_file::PkdnsConfig;

/// Safe the application wide configuration in a globally accessible way
/// so we don't need to pass variables all over.

pub static GLOBAL_CONFIG: Lazy<RwLock<PkdnsConfig>> = Lazy::new(|| RwLock::new(PkdnsConfig::default()));

/// Updates the global configuration safely.
pub fn update_global_config(new_value: PkdnsConfig) {
    let mut config = GLOBAL_CONFIG.write().unwrap();
    *config = new_value;
}

/// Returns a copy of the global configuration.
pub fn get_global_config() -> PkdnsConfig {
    let config = GLOBAL_CONFIG.read().unwrap();
    config.clone()
}