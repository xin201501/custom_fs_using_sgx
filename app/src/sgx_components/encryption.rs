//! This module contains the encryption manager for [aes] [xts_mode] encryption and decryption
use sgx_types::{error::SgxStatus, types::EnclaveId};
use sgx_urts::enclave::SgxEnclave;
use std::path::Path;
pub const DEFAULT_ENCLAVE_PATH: &str = "../bin/enclave.signed.so";
use once_cell::sync::OnceCell;
/// The global sgx environment
static GLOBAL_SGX_ENCRYPT_ENV: OnceCell<SgxEnclave> = OnceCell::new();

extern "C" {
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
}
/// [aes] [xts_mode] encryption and decryption manager
pub struct SGXEncryptionManager {
    /// sgx environment id, used to call enclave functions.
    /// we use **a global sgx environment** to avoid creating a new enclave for each encryption/decryption
    sgx_environment_id: EnclaveId,
    /// The key encryption key
    kek: [u8; 16],
    /// The disk sector size
    sector_size: usize,
}

impl SGXEncryptionManager {
    /// Create a new encryption manager
    /// # Parameters
    /// * `enclave_file_path` - The path to the enclave file
    /// * `kek` - The key encryption key
    /// * `sector_size` - The disk sector size
    /// # Returns
    /// * `Ok(Self)` - If the encryption manager was created successfully
    pub fn new(
        enclave_file_path: impl AsRef<Path>,
        kek: [u8; 16],
        sector_size: usize,
    ) -> anyhow::Result<Self> {
        let global_sgx_environment = GLOBAL_SGX_ENCRYPT_ENV
            .get_or_try_init(|| SgxEnclave::create(enclave_file_path, true))?;
        // let sgx_environment = SgxEnclave::create(enclave_file_path, true)?;
        Ok(Self {
            sgx_environment_id: global_sgx_environment.eid(),
            kek,
            sector_size,
        })
    }
}

impl SGXEncryptionManager {
    /// Encrypt a buffer using [aes] [xts_mode] with **128bit** block and **128bit** KEK
    pub fn sgx_aes_xts_128bit_128bit_kek_encryption(
        &self,
        plaintext: &[u8],
        first_sector_index: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; plaintext.len()];
        let sgx_status = unsafe {
            aes_xts_128bit_128bit_KEK_encryption(
                self.sgx_environment_id,
                &self.kek,
                plaintext.as_ptr(),
                plaintext.len(),
                self.sector_size,
                first_sector_index,
                ciphertext.as_mut_ptr(),
            )
        };

        match sgx_status {
            SgxStatus::Success => Ok(ciphertext),
            _ => Err(anyhow::anyhow!(
                "enclave run failed with status: {:?}",
                sgx_status
            )),
        }
    }
    /// Decrypt a buffer using [aes] [xts_mode] with **128bit** block and **128bit** KEK
    pub fn sgx_aes_xts_128bit_128bit_kek_decryption(
        &self,
        ciphertext: &[u8],
        first_sector_index: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let sgx_status = unsafe {
            aes_xts_128bit_128bit_KEK_decryption(
                self.sgx_environment_id,
                &self.kek,
                ciphertext.as_ptr(),
                ciphertext.len(),
                self.sector_size,
                first_sector_index,
                plaintext.as_mut_ptr(),
            )
        };

        match sgx_status {
            SgxStatus::Success => Ok(plaintext),
            _ => Err(anyhow::anyhow!(
                "enclave run failed with status: {:?}",
                sgx_status
            )),
        }
        // Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_aes_xts_128bit_128bit_kek_encryption_and_decryption() -> anyhow::Result<()> {
        // create an enclave
        let enclave = SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true)?;
        let mut plaintext = [5; 1024];
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
    fn test_aes_xts_128bit_128bit_kek_is_non_deterministic_encryption() -> anyhow::Result<()> {
        let enclave = SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true)?;
        let plaintext = [5; 1024];
        let mut ciphertext1 = [0u8; 1024];

        let sector_size = 0x200;
        let first_sector_index1 = 0;
        let mut sgx_status = unsafe {
            aes_xts_128bit_128bit_KEK_encryption(
                enclave.eid(),
                &[0u8; 16],
                plaintext.as_ptr(),
                plaintext.len(),
                sector_size,
                first_sector_index1,
                ciphertext1.as_mut_ptr(),
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
        // use another sector index to encrypt the same plaintext
        let first_sector_index2 = 1;
        let mut ciphertext2 = [0u8; 1024];
        sgx_status = unsafe {
            aes_xts_128bit_128bit_KEK_encryption(
                enclave.eid(),
                &[0u8; 16],
                plaintext.as_ptr(),
                plaintext.len(),
                sector_size,
                first_sector_index2,
                ciphertext2.as_mut_ptr(),
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
        assert_ne!(ciphertext1, ciphertext2);
        Ok(())
    }
}
