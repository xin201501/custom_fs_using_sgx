use arx_kw::{
    // (impl'd for AuthTag and re-exported by this crate)
    gx::GX,
    ArxKW, // From the subtle crate, allows for equality checking in constant time
};
pub(crate) fn wrap_key_into_vec(kek: &[u8; 16], key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut kek_expand = [0u8; 32];
    kek_expand.copy_from_slice(&kek.repeat(2));
    let wrapped_key = GX::encrypt_blob(&kek_expand, &key).unwrap();
    Ok(wrapped_key)
}
pub(crate) fn wrap_key(kek: &[u8; 16], key: &[u8], wrapped_key: &mut [u8]) -> anyhow::Result<()> {
    let mut kek_expand = [0u8; 32];
    kek_expand.copy_from_slice(&kek.repeat(2));
    let result = GX::encrypt_blob(&kek_expand, &key).unwrap();
    wrapped_key.copy_from_slice(&result);
    Ok(())
}
pub(crate) fn unwrap_key_into_vec(kek: &[u8; 16], wrapped_key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut kek_expand = [0u8; 32];
    kek_expand.copy_from_slice(&kek.repeat(2));
    let unwrapped_key = GX::decrypt_blob(&kek_expand, &wrapped_key).unwrap();
    Ok(unwrapped_key)
}
pub(crate) fn unwrap_key(
    kek: &[u8; 16],
    wrapped_key: &[u8],
    unwrapped_key: &mut [u8],
) -> anyhow::Result<()> {
    let mut kek_expand = [0u8; 32];
    kek_expand.copy_from_slice(&kek.repeat(2));
    let result = GX::decrypt_blob(&kek_expand, &wrapped_key).unwrap();
    unwrapped_key.copy_from_slice(&result);
    Ok(())
}
