use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn git_output(repo_root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=MDNS_SIEVE_VERSION");
    println!("cargo:rerun-if-env-changed=MDNS_SIEVE_REV_COUNT");
    println!("cargo:rerun-if-env-changed=MDNS_SIEVE_COMMIT");
    println!("cargo:rerun-if-changed=../VERSION");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let repo_root = Path::new(&manifest_dir).join("..");

    let base_version = env::var("MDNS_SIEVE_VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            fs::read_to_string(repo_root.join("VERSION"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    let rev_count = env::var("MDNS_SIEVE_REV_COUNT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| git_output(&repo_root, &["rev-list", "--count", "HEAD"]))
        .unwrap_or_else(|| "0".to_string());

    let commit = env::var("MDNS_SIEVE_COMMIT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let mut sha = git_output(&repo_root, &["rev-parse", "--short", "HEAD"])?;
            if let Some(status) = git_output(&repo_root, &["status", "--porcelain"]) {
                if !status.is_empty() {
                    sha.push('+');
                }
            }
            Some(sha)
        })
        .unwrap_or_else(|| "unknown".to_string());

    let full_version = format!("{base_version}-r{rev_count}");
    println!("cargo:rustc-env=MDNS_SIEVE_FULL_VERSION={full_version}");
    println!("cargo:rustc-env=MDNS_SIEVE_COMMIT={commit}");
}
