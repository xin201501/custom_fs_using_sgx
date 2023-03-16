// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..
use aes::cipher::generic_array::GenericArray;
use aes::Aes128;
use aes::NewBlockCipher;
use sgx_types::error::SgxStatus;
use xts_mode::Xts128;

#[no_mangle]
pub fn sample() -> SgxStatus {
    println!("in encalve:hello sgx");
    SgxStatus::Success
}
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn aes_xts_128bit_128bit_KEK_encryption(
    kek: &[u8; 16],
    plaintext: *const u8,
    plaintext_len: usize,
    sector_size: usize,
    sector_index: u64,
    ciphertext: *mut u8,
) {
    let plaintext = unsafe { core::slice::from_raw_parts(plaintext, plaintext_len) };
    let ciphertext = unsafe { core::slice::from_raw_parts_mut(ciphertext, plaintext_len) };
    ciphertext.copy_from_slice(plaintext);
    let key = [1u8; 32];
    let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));

    let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);
    xts.encrypt_area(
        ciphertext,
        sector_size, // `sector size` is equal to `block size`
        sector_index as u128,
        xts_mode::get_tweak_default,
    );
}
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn aes_xts_128bit_128bit_KEK_decryption(
    kek: &[u8; 16],
    ciphertext: *const u8,
    ciphertext_len: usize,
    sector_size: usize,
    sector_index: u64,
    plaintext: *mut u8,
) {
    let ciphertext = unsafe { core::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let plaintext = unsafe { core::slice::from_raw_parts_mut(plaintext, ciphertext_len) };
    plaintext.copy_from_slice(ciphertext);
    let key = [1u8; 32];
    let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));

    let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);
    xts.decrypt_area(
        plaintext,
        sector_size, // `sector size` is equal to `block size`
        sector_index as u128,
        xts_mode::get_tweak_default,
    );
}
#[no_mangle]
pub extern "C" fn test_xts_mode1() -> SgxStatus {
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
