//! Embeds the pinned Xray version and binary SHA-256 for the target platform
//! (from `xray/xray.lock.json`), so the helper can refuse to launch any other binary.

fn main() {
    println!("cargo:rerun-if-changed=xray/xray.lock.json");
    let lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("xray/xray.lock.json").expect("read xray/xray.lock.json"))
            .expect("parse xray/xray.lock.json");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let platform = format!(
        "{}-{}",
        match os.as_str() {
            "windows" => "windows",
            "macos" => "macos",
            other => other,
        },
        match arch.as_str() {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            other => other,
        }
    );
    let hash = lock["assets"][&platform]["binarySha256"].as_str().unwrap_or("");
    // Unsupported platforms (e.g. Linux dev builds) get an empty pin: Xray will not be launched.
    println!("cargo:rustc-env=PP_XRAY_SHA256={hash}");
    println!("cargo:rustc-env=PP_XRAY_VERSION={}", lock["version"].as_str().unwrap_or(""));
}
