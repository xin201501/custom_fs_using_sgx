use std::path::Path;

use super::key_management::{KeyManager, DEFAULT_KEY_MANAGER_PATH};
use aes::cipher::generic_array::GenericArray;
use aes::Aes128;
use aes::NewBlockCipher;
use sgx_types::error::SgxStatus;
use sgx_unit_test::run_unit_tests;
use xts_mode::Xts128;

fn lookup_key(path: impl AsRef<Path>) -> anyhow::Result<[u8; 32]> {
    let key_manager = KeyManager::new(path)?;
    // dbg!(&key_manager);
    Ok(key_manager.data_encryption_key_ref().to_owned())
    
}

fn aes_xts_128bit_128bit_key_encryption(
    key: &[u8; 32],
    plaintext: &[u8],
    sector_size: usize,
    sector_index: u64,
) -> Vec<u8> {
    let mut ciphertext = plaintext.to_owned();
    ciphertext.copy_from_slice(plaintext);
    let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));

    let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);
    xts.encrypt_area(
        &mut ciphertext,
        sector_size, // `sector size` is equal to `block size`
        sector_index as u128,
        xts_mode::get_tweak_default,
    );
    ciphertext
}

fn aes_xts_128bit_128bit_key_decryption(
    key: &[u8; 32],
    ciphertext: &[u8],
    sector_size: usize,
    sector_index: u64,
) -> Vec<u8> {
    let mut plaintext = ciphertext.to_owned();
    plaintext.copy_from_slice(ciphertext);
    let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));

    let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);
    xts.decrypt_area(
        &mut plaintext,
        sector_size, // `sector size` is equal to `block size`
        sector_index as u128,
        xts_mode::get_tweak_default,
    );
    plaintext
}

#[no_mangle]
pub unsafe extern "C" fn aes_xts_128bit_key_in_sgx_encryption(
    plaintext: *const u8,
    plaintext_len: usize,
    sector_size: usize,
    sector_index: u64,
    ciphertext: *mut u8,
) {
    let plaintext = std::slice::from_raw_parts(plaintext, plaintext_len);
    let ciphertext = std::slice::from_raw_parts_mut(ciphertext, plaintext_len);
    
    let key = lookup_key(DEFAULT_KEY_MANAGER_PATH).expect("lookup data encryption key failed"); //TODO

    let result = aes_xts_128bit_128bit_key_encryption(&key, plaintext, sector_size, sector_index);
    ciphertext.copy_from_slice(&result);
}

#[no_mangle]
pub unsafe extern "C" fn aes_xts_128bit_key_in_sgx_decryption(
    ciphertext: *const u8,
    ciphertext_len: usize,
    sector_size: usize,
    sector_index: u64,
    plaintext: *mut u8,
) {
    let ciphertext = std::slice::from_raw_parts(ciphertext, ciphertext_len);
    let plaintext = std::slice::from_raw_parts_mut(plaintext, ciphertext_len);
    let key = lookup_key(DEFAULT_KEY_MANAGER_PATH).expect("lookup data encryption key failed!"); //TODO

    let result = aes_xts_128bit_128bit_key_decryption(&key, ciphertext, sector_size, sector_index);
    plaintext.copy_from_slice(&result);
}

fn test_xts_mode1() -> SgxStatus {
    use xts_mode::get_tweak_default;

    // Load the encryption key
    let key = [1; 32];
    let plaintext = [5; 0x400];

    // Load the data to be encrypted
    let mut buffer = plaintext.to_owned();

    let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));

    let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);

    let sector_size = 0x200;
    let first_sector_index = 0;

    // Encrypt data in the buffer
    xts.encrypt_area(
        &mut buffer,
        sector_size,
        first_sector_index,
        get_tweak_default,
    );

    // Decrypt data in the buffer
    xts.decrypt_area(
        &mut buffer,
        sector_size,
        first_sector_index,
        get_tweak_default,
    );

    assert_eq!(&buffer[..], &plaintext[..]);
    SgxStatus::Success
}

fn test_aes_xts_128bit_128bit_kek_encryption_and_decryption() {
    // create an enclave
    let plaintext = [5; 1024];

    let sector_size = 0x200;
    let first_sector_index = 0;
    let key = [1u8; 32];
    let ciphertext = unsafe {
        aes_xts_128bit_128bit_key_encryption(&key, &plaintext, sector_size, first_sector_index)
    };

    let recovered_plaintext = unsafe {
        aes_xts_128bit_128bit_key_decryption(&key, &ciphertext, sector_size, first_sector_index)
    };

    assert_eq!(recovered_plaintext, [5; 1024]);
}

fn test_aes_xts_128bit_128bit_kek_is_non_deterministic_encryption() {
    let plaintext = [5; 1024];
    let key = [1u8; 32];
    let sector_size = 0x200;
    let first_sector_index1 = 0;
    let ciphertext1 = unsafe {
        aes_xts_128bit_128bit_key_encryption(&key, &plaintext, sector_size, first_sector_index1)
    };

    // use another sector index to encrypt the same plaintext
    let first_sector_index2 = 1;
    let ciphertext2 = unsafe {
        aes_xts_128bit_128bit_key_encryption(&key, &plaintext, sector_size, first_sector_index2)
    };

    assert_ne!(ciphertext1, ciphertext2);
}
#[no_mangle]
pub extern "C" fn run_encryption_tests() {
    let failed_tests_amount = run_unit_tests!(
        test_aes_xts_128bit_128bit_kek_encryption_and_decryption,
        test_aes_xts_128bit_128bit_kek_is_non_deterministic_encryption,
        test_xts_mode1
    );
    if failed_tests_amount > 0 {
        panic!("{} test(s) failed", failed_tests_amount);
    }
}
