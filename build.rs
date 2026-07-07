fn main() {
    // Expose the build target triple so `binswap::current_target()` can verify
    // architecture match at runtime without pulling in a target-detection crate.
    println!(
        "cargo:rustc-env=BINSWAP_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
}
