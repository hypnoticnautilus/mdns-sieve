use std::env;
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

fn version_from_git_describe(repo_root: &Path) -> (String, String) {
    if let Some(desc) = git_output(repo_root, &["describe", "--tags", "--match", "v*", "--long"]) {
        // Format: <tag>-<rev_count>-g<sha> (split from the right to support tags with hyphens)
        let mut parts = desc.rsplitn(3, '-');
        if let (Some(_sha), Some(rev), Some(tag)) = (parts.next(), parts.next(), parts.next()) {
            let ver = tag.strip_prefix('v').unwrap_or(tag).to_string();
            return (ver, rev.to_string());
        }
    }
    let rev_count = git_output(repo_root, &["rev-list", "--count", "HEAD"])
        .unwrap_or_else(|| "0".to_string());
    ("0.0.0".to_string(), rev_count)
}

fn main() {
    println!("cargo:rerun-if-env-changed=MDNS_SIEVE_VERSION");
    println!("cargo:rerun-if-env-changed=MDNS_SIEVE_REV_COUNT");
    println!("cargo:rerun-if-env-changed=MDNS_SIEVE_COMMIT");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
    println!("cargo:rerun-if-changed=../.git/refs/tags");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let repo_root = Path::new(&manifest_dir).join("..");

    let env_version = env::var("MDNS_SIEVE_VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let env_rev = env::var("MDNS_SIEVE_REV_COUNT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let (base_version, rev_count) = match (env_version, env_rev) {
        (Some(v), Some(r)) => (v, r),
        (v_opt, r_opt) => {
            let (git_v, git_r) = version_from_git_describe(&repo_root);
            (v_opt.unwrap_or(git_v), r_opt.unwrap_or(git_r))
        }
    };

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
