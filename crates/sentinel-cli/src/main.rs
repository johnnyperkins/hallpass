//! Sentinel CLI binary entry point.

#![deny(unsafe_code)]

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let code = rt.block_on(sentinel_cli::run(&argv));
    std::process::exit(code);
}
