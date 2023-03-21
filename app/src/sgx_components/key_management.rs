//! This module is about KEK creation and replacement
use std::ffi::c_char;

use super::DEFAULT_ENCLAVE_PATH;
use once_cell::sync::OnceCell;
use sgx_types::{error::SgxStatus, types::EnclaveId};
use sgx_urts::enclave::SgxEnclave;

/// The global sgx environment
static GLOBAL_SGX_KEY_MANAGE_ENV: OnceCell<SgxEnclave> = OnceCell::new();
extern "C" {
    fn create_user_kek(
        eid: EnclaveId,
        user_id: u16,
        user_password: *const u8,
        user_password_len: usize,
        user_kek: &mut [u8; 16],
    ) -> SgxStatus;
    fn test_new_kek_manager(eid: EnclaveId, kek_path: *const c_char) -> SgxStatus;
}

/// The key management manager
pub struct KeyManager {
    /// sgx environment id, used to call enclave functions.\
    /// we use **a global sgx environment** to avoid creating a new enclave for each encryption/decryption
    sgx_environment_id: EnclaveId,
}
impl KeyManager {
    pub fn new() -> anyhow::Result<Self> {
        let global_sgx_environment = GLOBAL_SGX_KEY_MANAGE_ENV
            .get_or_try_init(|| SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true))?;
        Ok(Self {
            sgx_environment_id: global_sgx_environment.eid(),
        })
    }
}

impl KeyManager {
    pub fn sgx_create_user_kek(&self, user_id: u16, user_password: impl AsRef<[u8]>) -> [u8; 16] {
        let user_password = user_password.as_ref();
        let mut user_kek = [0u8; 16];
        unsafe {
            create_user_kek(
                self.sgx_environment_id,
                user_id,
                user_password.as_ptr(),
                user_password.len(),
                &mut user_kek,
            )
        };
        user_kek
    }
}

#[cfg(test)]
mod tests {
    extern "C" {
        fn run_key_management_rust_api_tests(eid: EnclaveId) -> SgxStatus;
        fn run_key_management_c_api_tests(eid: EnclaveId) -> SgxStatus;
        fn test_argon2_kdf(eid: EnclaveId) -> SgxStatus;
    }
    use super::*;
    // test [Argon2] crate works in sgx
    #[test]
    fn test_sgx_argon2_kdf() -> anyhow::Result<()> {
        //create an enclave
        let enclave = SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true)?;
        let status = unsafe { test_argon2_kdf(enclave.eid()) };
        match status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!("test_failed")),
        }
    }
    #[test]
    fn sgx_key_management_rust_api_tests() -> anyhow::Result<()> {
        //create an enclave
        let enclave = SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true)?;
        let test_driver_run_status = unsafe { run_key_management_rust_api_tests(enclave.eid()) };
        match test_driver_run_status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!("test_failed")),
        }
    }

    #[test]
    fn sgx_key_management_c_api_tests() -> anyhow::Result<()> {
        //create an enclave
        let enclave = SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true)?;
        let test_driver_run_status = unsafe { run_key_management_c_api_tests(enclave.eid()) };
        match test_driver_run_status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!("test failed")),
        }
    }
}
