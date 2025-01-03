mod config_file;
mod global;

pub use config_file::{read_or_create_config, read_or_create_from_dir};
pub use global::{update_global_config, get_global_config};