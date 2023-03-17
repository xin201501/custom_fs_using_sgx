use bincode::config;
use serde::Serialize;

/// cacluate [blake3] hash of a serilizeable object
pub fn digest<T: Serialize>(t: &T) -> anyhow::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let config = config::legacy();
    hasher.update(&bincode::serde::encode_to_vec(t, config)?);
    let mut hash = hasher.finalize_xof();
    let mut output = [0u8; 32];
    hash.fill(&mut output);
    Ok(output)
}
