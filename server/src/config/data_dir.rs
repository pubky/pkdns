use dyn_clone::DynClone;
use std::path::Path;

use crate::config::ConfigToml;

/// A trait for the data directory.
/// Used to abstract the data directory from the rest of the code.
///
/// To create a real dir and a test dir.
pub trait DataDir: std::fmt::Debug + DynClone + Send + Sync {
    /// Returns the path to the data directory.
    fn path(&self) -> &Path;
    /// Makes sure the data directory exists.
    /// Create the directory if it doesn't exist.
    fn ensure_data_dir_exists_and_is_writable(&self) -> anyhow::Result<()>;

    /// Reads the config file from the data directory.
    /// Creates a default config file if it doesn't exist.
    fn read_or_create_config_file(&self) -> anyhow::Result<ConfigToml>;
}

dyn_clone::clone_trait_object!(DataDir);
