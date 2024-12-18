use std::env;
use tracing::Level;
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/**
 * Sets `RUST_BACKTRACE=full` as default so we always get a full stacktrace
 * on an error.
 */
pub(crate) fn set_full_stacktrace_as_default() -> () {
    let key = "RUST_BACKTRACE";
    let value = env::var(key);
    if value.is_ok() {
        return;
    }
    env::set_var(key, "1");
}

pub(crate) fn enable_logging(verbose: bool) {
    let key = "RUST_LOG";
    let value = match env::var(key) {
        Ok(val) => val,
        Err(_) => "".to_string(),
    };

    if value.len() > 0 {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
        tracing::info!("Used RUST_LOG={} env variable to set logging output.", value);
        if verbose {
            tracing::warn!("RUST_LOG= is set. Ignore --verbose flag.")
        }
        return;
    }

    let regular_filter = tracing_subscriber::filter::Targets::new()
        .with_target("pkdns", Level::INFO)
        .with_target("mainline", Level::WARN);

    let verbose_filter = tracing_subscriber::filter::Targets::new()
        .with_target("pkdns", Level::DEBUG)
        .with_target("mainline", Level::WARN);

    let mut filter: Targets = regular_filter;
    if verbose {
        filter = verbose_filter;
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    if verbose {
        tracing::info!("Verbose mode enabled.");
    }
}
