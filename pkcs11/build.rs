use std::{env, path::Path, process::Command};

fn main() {
    if cfg!(target_os = "windows") {
        // Only run for release events in the GitHub pipeline
        if env::var("GITHUB_EVENT_NAME").unwrap_or_default() == "release" {
            windows_version_file();
        }
    }
}

fn windows_version_file() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let rc_file = Path::new(&manifest_dir).join("version.rc");
    let res_file = Path::new(&out_dir).join("version.res");

    // Compile resource file
    let output = Command::new("rc")
        .args(["/fo", res_file.to_str().unwrap(), rc_file.to_str().unwrap()])
        .output()
        .expect("Failed to run resource compiler. Make sure the Windows Software Development Kit (SDK) is installed and available in the Path environment variable.");

    if !output.status.success() {
        panic!(
            "Resource compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Link resource file
    println!("cargo:rustc-link-arg={}", res_file.to_str().unwrap());
    println!("cargo:rerun-if-changed={}", rc_file.to_str().unwrap());
}
