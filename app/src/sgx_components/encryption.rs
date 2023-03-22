//! This module contains the encryption manager for [aes] [xts_mode] encryption and decryption
use once_cell::sync::OnceCell;
use sgx_types::{error::SgxStatus, types::EnclaveId};
use sgx_urts::enclave::SgxEnclave;
use std::path::Path;
/// The global sgx environment
static GLOBAL_SGX_ENCRYPT_ENV: OnceCell<SgxEnclave> = OnceCell::new();

extern "C" {
    fn aes_xts_128bit_key_in_sgx_encryption(
        eid: EnclaveId,
        plaintext: *const u8,
        plaintext_len: usize,
        sector_size: usize,
        sector_index: u64,
        ciphertext: *mut u8,
    ) -> SgxStatus;
    fn aes_xts_128bit_key_in_sgx_decryption(
        eid: EnclaveId,
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
    pub fn new(enclave_file_path: impl AsRef<Path>, sector_size: usize) -> anyhow::Result<Self> {
        let global_sgx_environment = GLOBAL_SGX_ENCRYPT_ENV
            .get_or_try_init(|| SgxEnclave::create(enclave_file_path, true))?;
        // let sgx_environment = SgxEnclave::create(enclave_file_path, true)?;
        Ok(Self {
            sgx_environment_id: global_sgx_environment.eid(),
            sector_size,
        })
    }
}

impl SGXEncryptionManager {
    /// Encrypt a buffer using [aes] [xts_mode] with **128bit** block and **128bit** KEK
    pub fn sgx_aes_xts_128bit_key_in_sgx_encryption(
        &self,
        plaintext: &[u8],
        first_sector_index: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; plaintext.len()];
        let sgx_status = unsafe {
            aes_xts_128bit_key_in_sgx_encryption(
                self.sgx_environment_id,
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
    pub fn sgx_aes_xts_128bit_key_in_sgx_decryption(
        &self,
        ciphertext: &[u8],
        first_sector_index: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let sgx_status = unsafe {
            aes_xts_128bit_key_in_sgx_decryption(
                self.sgx_environment_id,
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
    }
}

#[cfg(test)]
mod tests {
    use crate::sgx_components::DEFAULT_ENCLAVE_PATH;
    use sgx_types::{error::SgxStatus, types::EnclaveId};
    use sgx_urts::enclave::SgxEnclave;

    extern "C" {
        fn run_encryption_tests(eid: EnclaveId) -> SgxStatus;
    }

    #[test]
    fn run_sgx_encryption_module_tests() -> anyhow::Result<()> {
        let enclave = SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true)?;
        let test_driver_run_status = unsafe { run_encryption_tests(enclave.eid()) };
        match test_driver_run_status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!("test failed")),
        }
    }
}
