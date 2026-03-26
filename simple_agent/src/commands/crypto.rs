/// File hashing commands: md5, sha1, sha256.
/// Cross-platform — pure Rust via RustCrypto crates.

use std::io::Read;
use digest::Digest;

fn hash_file<D: Digest>(path: &str) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("{}: {}", path, e))?;
    let mut hasher = D::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(hex)
}

pub fn md5(args: &[String]) -> anyhow::Result<String> {
    let path = args.first()
        .ok_or_else(|| anyhow::anyhow!("md5: <filepath> required"))?;
    let h = hash_file::<md5::Md5>(path)?;
    Ok(format!("MD5 ({}) = {}", path, h))
}

pub fn sha1(args: &[String]) -> anyhow::Result<String> {
    let path = args.first()
        .ok_or_else(|| anyhow::anyhow!("sha1: <filepath> required"))?;
    let h = hash_file::<sha1::Sha1>(path)?;
    Ok(format!("SHA1 ({}) = {}", path, h))
}

pub fn sha256(args: &[String]) -> anyhow::Result<String> {
    let path = args.first()
        .ok_or_else(|| anyhow::anyhow!("sha256: <filepath> required"))?;
    let h = hash_file::<sha2::Sha256>(path)?;
    Ok(format!("SHA256 ({}) = {}", path, h))
}
