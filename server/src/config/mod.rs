mod config_file;
mod global;
mod data_dir;
mod persistent_data_dir;
#[cfg(test)]
mod mock_data_dir;

pub use config_file::{read_or_create_config, read_or_create_from_dir, ConfigToml};
pub use global::{get_global_config, update_global_config};
pub use data_dir::DataDir;
#[cfg(test)]
pub use mock_data_dir::MockDataDir;
pub use persistent_data_dir::PersistentDataDir;