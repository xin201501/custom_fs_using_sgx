use argon2::Argon2;
use sgx_unit_test::run_unit_tests;

/// ref: https://docs.rs/argon2/0.5.0/argon2
fn test_argon2_kdf() {
    let password = b"hunter42"; // Bad password; don't actually use!
    let salt = b"example salt"; // Salt should be unique per password
    let mut output_key_material = [0u8; 32]; // Can be any desired size
    Argon2::default()
        .hash_password_into(password, salt, &mut output_key_material)
        .unwrap();
}
/// ref: https://crates.io/crates/arx-kw
fn test_arx_kw() {
    use arx_kw::{
        // (impl'd for AuthTag and re-exported by this crate)
        assert_ct_eq,
        gx::GX,
        ArxKW,
        ConstantTimeEq, // From the subtle crate, allows for equality checking in constant time
    };
    use hex::FromHex;
    let key =
        <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    // The plaintext secret key we want to store/transport securely
    let plaintext =
        <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
            .unwrap();

    /*
     * Expected output:
     * A Vec<u8> containing the authentication tag followed by the ciphertext containing the
     * wrapped key. We can treat this as an opaque blob when using the encrypt_blob and decrypt_blob
     * methods, meaning we don't have to manually manage authentication tags or nonces.
     */
    let blob_expected = <[u8; 48]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc652f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3").unwrap();

    /*
     * Key wrapping performed in one line, simply passing the
     * encryption key and the plaintext to be encrypted.
     */
    let blob = GX::encrypt_blob(&key, &plaintext).unwrap();
    assert_ct_eq!(blob, &blob_expected);

    /*
     * Decryption likewise is done in one line, passing the key and the blob to be decrypted.
     * The authentication tag is checked to match the ciphertext
     * during decryption and will return an error if the tags do not match.
     * Returns the decrypted plaintext if successful, otherwise an error.
     */
    let decrypted_plaintext = GX::decrypt_blob(&key, &blob).unwrap();
    assert_ct_eq!(plaintext, &decrypted_plaintext);
}
#[no_mangle]
pub extern "C" fn test_third_party_crates() {
    let failed_tests_amount = run_unit_tests!(test_argon2_kdf, test_arx_kw);
    if failed_tests_amount > 0 {
        panic!("{} test(s) failed!", failed_tests_amount);
    }
}
