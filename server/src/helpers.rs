use std::env;

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
    env::set_var(key, "full");
}