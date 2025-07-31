use crate::config::{ConfigToml, DataDir};

#[derive(Debug, Clone, Default)]
pub struct AppContext {
    pub config: ConfigToml,
}

impl AppContext {
    pub fn from_data_dir(data_dir: impl DataDir) -> Result<Self, anyhow::Error> {
        data_dir.ensure_data_dir_exists_and_is_writable()?;
        let config = data_dir.read_or_create_config_file()?;
        Ok(Self { config })
    }

    #[cfg(test)]
    pub fn test() -> Self {
        Self {
            config: ConfigToml::test(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::MockDataDir;

    use super::*;

    #[test]
    fn test_from_data_dir() {
        let data_dir = MockDataDir::test();
        let _ = AppContext::from_data_dir(data_dir).unwrap();
    }
}
