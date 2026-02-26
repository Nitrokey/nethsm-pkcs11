use std::{env, fs::File, io::Write, path::Path, process::Command, str::FromStr};

fn main() {
    if cfg!(target_os = "windows") {
        versioninfo();
    }
}

const RC_FILENAME: &str = "version.rc";
const RES_FILENAME: &str = "version.res";
const RC_TEMPLATE: &str = r##"
#include <windows.h>

VS_VERSION_INFO VERSIONINFO
FILEVERSION     0,0,0,0
PRODUCTVERSION  {PRODUCT_VERSION}
FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
FILEFLAGS       {FILEFLAGS}
FILEOS          VOS__WINDOWS32
FILETYPE        VFT_DLL
FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904E4"  // US English, ANSI Latin 1; Western European (Windows)
        BEGIN
            VALUE "CompanyName",      "Nitrokey GmbH"
            VALUE "FileDescription",  "PKCS#11 module for the Nitrokey NetHSM"
            VALUE "FileVersion",      "0.0.0.0\0"
            VALUE "ProductVersion",   "{PRODUCT_VERSION_STR}\0"
            VALUE "InternalName",     "nethsm_pkcs11"
            VALUE "LegalCopyright",   "Nitrokey GmbH and contributors"
            VALUE "OriginalFilename", "nethsm_pkcs11.dll"
            VALUE "ProductName",      "NetHSM PKCS#11 module"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1252  // US English, ANSI Latin 1; Western European (Windows)
    END
END"##;

fn versioninfo() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let rc_path = Path::new(&out_dir).join(RC_FILENAME);
    let res_path = Path::new(&out_dir).join(RES_FILENAME);

    let major =
        u16::from_str(env!("CARGO_PKG_VERSION_MAJOR")).expect("Can not parse major to u16.");
    let minor =
        u16::from_str(env!("CARGO_PKG_VERSION_MINOR")).expect("Can not parse minor to u16.");
    let patch =
        u16::from_str(env!("CARGO_PKG_VERSION_PATCH")).expect("Can not parse patch to u16.");
    let pre = env!("CARGO_PKG_VERSION_PRE");

    let fileflags = if pre.is_empty() {
        "0x0"
    } else {
        "VS_FF_PRERELEASE"
    };

    let resource_script = String::from(RC_TEMPLATE)
        .replace(
            "{PRODUCT_VERSION}",
            &format!("{},{},{},{}", major, minor, patch, 0),
        )
        .replace("{PRODUCT_VERSION_STR}", env!("CARGO_PKG_VERSION"))
        .replace("{FILEFLAGS}", fileflags);

    let mut f = File::create(rc_path.to_str().unwrap()).unwrap();
    f.write_all(resource_script.as_bytes())
        .expect("Could not write resource script.");

    let output = Command::new("rc")
        .args(["/fo", res_path.to_str().unwrap(), rc_path.to_str().unwrap()])
        .output()
        .expect("Failed to run resource compiler. Make sure the Windows Software Development Kit (SDK) is installed and available in the Path environment variable.");

    if !output.status.success() {
        panic!(
            "Resource compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Only run for release events in the GitHub pipeline
    if env::var("GITHUB_EVENT_NAME").unwrap_or_default() == "release" {
        println!("cargo:rustc-link-arg={}", res_path.to_str().unwrap());
        println!("cargo:rerun-if-changed=Cargo.toml");
    }
}
