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
use sgx_types::error::SgxStatus;

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn sample() -> SgxStatus {
    println!("Hello world!");

    SgxStatus::Success
}

#[no_mangle]
pub extern "C" fn test_xts_mode1() -> SgxStatus {
    use aes::NewBlockCipher;
    use aes::Aes128;
use xts_mode::{Xts128, get_tweak_default};

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
xts.encrypt_area(&mut buffer, sector_size, first_sector_index, get_tweak_default);

// Decrypt data in the buffer
xts.decrypt_area(&mut buffer, sector_size, first_sector_index, get_tweak_default);

assert_eq!(&buffer[..], &plaintext[..]);
SgxStatus::Success
}

#[no_mangle]
pub extern "C" fn test_xts_mode2() -> SgxStatus {
    use aes::{Aes128, NewBlockCipher};
    use xts_mode::{Xts128, get_tweak_default};
    
    // Load the encryption key
    let key = [1; 32];
    let plaintext = [5; 0x200];
    
    // Load the data to be encrypted
    let mut buffer = plaintext.to_owned();
    
    let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));
    
    let xts = Xts128::<Aes128>::new(cipher_1, cipher_2);
    
    let tweak = get_tweak_default(0); // 0 is the sector index
    
    // Encrypt data in the buffer
    xts.encrypt_sector(&mut buffer, tweak);
    
    // Decrypt data in the buffer
    xts.decrypt_sector(&mut buffer, tweak);
    
    assert_eq!(&buffer[..], &plaintext[..]);
    SgxStatus::Success
}