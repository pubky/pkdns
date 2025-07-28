//! Safe the application wide configuration in a globally accessible way
//! so we don't need to pass variables all over.

use super::config_file::ConfigToml;
use once_cell::sync::Lazy;
use std::sync::RwLock;

pub static GLOBAL_CONFIG: Lazy<RwLock<ConfigToml>> = Lazy::new(|| RwLock::new(ConfigToml::default()));

/// Updates the global configuration safely.
pub fn update_global_config(new_value: ConfigToml) {
    let mut config = match GLOBAL_CONFIG.write() {
        Ok(config) => config,
        Err(e) => {
            // Lock poisoned, this should never happen.
            panic!("Failed to update global config: {}", e);
        }
    };

    *config = new_value;
}

/// Returns a copy of the global configuration.
pub fn get_global_config() -> ConfigToml {
    let config = match GLOBAL_CONFIG.read() {
        Ok(config) => config,
        Err(e) => {
            // Lock poisoned, this should never happen.
            panic!("Failed to read global config: {}", e);
        }
    };
    config.clone()
}
