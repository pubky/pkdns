use std::path::Path;

use super::DataDir;

/// Mock data directory for testing.
///
/// It uses a temporary directory to store all data in. The data is removed as soon as the object is dropped.
///

#[derive(Debug, Clone)]
pub struct MockDataDir {
    pub(crate) temp_dir: std::sync::Arc<tempfile::TempDir>,
    /// The configuration for the homeserver.
    pub config_toml: super::ConfigToml,
}

impl MockDataDir {
    /// Create a new DataDirMock with a temporary directory.
    ///
    /// If keypair is not provided, a new one will be generated.
    pub fn new(config_toml: super::ConfigToml) -> anyhow::Result<Self> {
        Ok(Self {
            temp_dir: std::sync::Arc::new(tempfile::TempDir::new()?),
            config_toml,
        })
    }

    /// Creates a mock data directory with a config and keypair appropriate for testing.
    pub fn test() -> Self {
        let config = super::ConfigToml::test();
        Self::new(config).expect("failed to create MockDataDir")
    }
}

impl Default for MockDataDir {
    fn default() -> Self {
        Self::test()
    }
}

impl DataDir for MockDataDir {
    fn path(&self) -> &Path {
        self.temp_dir.path()
    }

    fn ensure_data_dir_exists_and_is_writable(&self) -> anyhow::Result<()> {
        Ok(()) // Always ok because this is validated by the tempfile crate.
    }

    fn read_or_create_config_file(&self) -> anyhow::Result<super::ConfigToml> {
        Ok(self.config_toml.clone())
    }
}
