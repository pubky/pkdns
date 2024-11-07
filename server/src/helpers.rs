use std::env;
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};
use tracing::{Level};

/**
 * Sets `RUST_BACKTRACE=full` as default so we always get a full stacktrace
 * on an error.
 */
pub (crate) fn set_full_stacktrace_as_default() -> () {
    let key = "RUST_BACKTRACE";
    let value = env::var(key);
    if value.is_ok() {
        return;
    }
    env::set_var(key, "1");
}


pub (crate) fn enable_logging(verbose: bool) {
    let key = "RUST_LOG";
    let is_env_var_set = env::var(key).is_ok();

    if is_env_var_set {
        tracing_subscriber::fmt().init();
        if verbose {
            tracing::warn!("Custom RUST_LOG= env variable is set. Ignore --verbose flag.")
        }
        return
    }

    let regular_filter = tracing_subscriber::filter::Targets::new()
    .with_target("pkdns", Level::INFO)
    .with_target("any_dns", Level::INFO)
    .with_target("mainline", Level::WARN);

    let verbose_filter = tracing_subscriber::filter::Targets::new()
    .with_target("pkdns", Level::DEBUG)
    .with_target("any_dns", Level::DEBUG)
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