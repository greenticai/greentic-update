fn main() {
    // Expose the build target triple so `binswap::current_target()` can verify
    // architecture match at runtime without pulling in a target-detection crate.
    // Only emitted when the `binswap` feature is active — the env var is consumed
    // inside #[cfg(feature = "binswap")] code, so it is always available when
    // needed, and non-binswap builds avoid the cache-key side effect.
    if std::env::var("CARGO_FEATURE_BINSWAP").is_ok() {
        println!(
            "cargo:rustc-env=BINSWAP_TARGET={}",
            std::env::var("TARGET").unwrap()
        );
    }
}
