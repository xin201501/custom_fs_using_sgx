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
use sgx_types::{error::SgxStatus, types::EnclaveId};
extern "C" {
    fn sample(eid: EnclaveId, ret: *mut SgxStatus) -> SgxStatus;
    fn aes_xts_128bit_128bit_KEK_encryption(
        eid: EnclaveId,
        kek: &[u8; 16],
        plaintext: *const u8,
        plaintext_len: usize,
        sector_size: usize,
        sector_index: u64,
        ciphertext: *mut u8,
    ) -> SgxStatus;
    fn aes_xts_128bit_128bit_KEK_decryption(
        eid: EnclaveId,
        kek: &[u8; 16],
        ciphertext: *const u8,
        ciphertext_len: usize,
        sector_size: usize,
        sector_index: u64,
        plaintext: *mut u8,
    ) -> SgxStatus;
    fn test_xts_mode1(eid: EnclaveId, retval: *mut SgxStatus) -> SgxStatus;
}

#[cfg(test)]
mod tests {
    use sgx_urts::enclave::SgxEnclave;

    use super::*;
    /// Test AES-XTS 128-bit KEK encryption
    /// Reference:https://docs.rs/xts-mode/0.4.0/xts_mode/index.html
    #[test]
    fn test_aes_xts_128bit_128bit_kek_encryption_and_decryption() -> anyhow::Result<()> {
        // create an enclave
        let enclave = SgxEnclave::create("../bin/enclave.signed.so", true)?;
        let mut plaintext = [5; 0x400];
        let mut ciphertext = [0u8; 1024];

        let sector_size = 0x200;
        let first_sector_index = 0;
        let mut sgx_status = unsafe {
            aes_xts_128bit_128bit_KEK_encryption(
                enclave.eid(),
                &[0u8; 16],
                plaintext.as_ptr(),
                plaintext.len(),
                sector_size,
                first_sector_index,
                ciphertext.as_mut_ptr(),
            )
        };

        match sgx_status {
            SgxStatus::Success => (),
            _ => {
                return Err(anyhow::anyhow!(
                    "enclave run failed with status: {:?}",
                    sgx_status
                ))
            }
        };

        sgx_status = unsafe {
            aes_xts_128bit_128bit_KEK_decryption(
                enclave.eid(),
                &[0u8; 16],
                ciphertext.as_ptr(),
                ciphertext.len(),
                sector_size,
                first_sector_index,
                plaintext.as_mut_ptr(),
            )
        };

        match sgx_status {
            SgxStatus::Success => (),
            _ => {
                return Err(anyhow::anyhow!(
                    "enclave run failed with status: {:?}",
                    sgx_status
                ))
            }
        };

        assert_eq!(plaintext, [5; 0x400]);
        Ok(())
    }
    #[test]
    fn test_sample() -> anyhow::Result<()> {
        // create an enclave
        let enclave = SgxEnclave::create("../bin/enclave.signed.so", true)?;
        let mut sgx_status = SgxStatus::BadStatus;
        unsafe { test_xts_mode1(enclave.eid(), &mut sgx_status) };
        // match `sgx_status`
        match sgx_status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!(
                "enclave run failed with status: {:?}",
                sgx_status
            )),
        }
    }
}
