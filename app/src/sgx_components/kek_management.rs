//! This module is about KEK creation and replacement
use once_cell::sync::OnceCell;
use sgx_types::{error::SgxStatus, types::EnclaveId};
use sgx_urts::enclave::SgxEnclave;
use std::path::Path;
pub const DEFAULT_KEK_MANAGER_PATH: &str = "/tmp/kek_manager";
/// The global sgx environment
static GLOBAL_SGX_KEK_MANAGE_ENV: OnceCell<SgxEnclave> = OnceCell::new();
extern "C" {
    fn init_kek_manager(eid: EnclaveId, kek_path: *const u8, kek_path_len: usize) -> SgxStatus;
    fn create_user_kek(
        eid: EnclaveId,
        ret: *mut SgxStatus,
        user_id: u32,
        user_password: *const u8,
        user_password_len: usize,
    ) -> SgxStatus;

    fn generate_random_wrapped_key(
        eid: EnclaveId,
        ret: *mut SgxStatus,
        user_id: u32,
        user_password: *const u8,
        user_password_len: usize,
        wrapped_key: *mut u8,
        wrapped_key_len: usize,
    ) -> SgxStatus;

    fn check_user_password_outside_sgx(
        eid: EnclaveId,
        ret: *mut SgxStatus,
        user_id: u32,
        user_password: *const u8,
        user_password_len: usize,
    ) -> SgxStatus;
    fn update_user_kek(
        eid: EnclaveId,
        ret: *mut SgxStatus,
        user_id: u32,
        old_user_password: *const u8,
        old_user_password_len: usize,
        new_user_password: *const u8,
        new_user_password_len: usize,
    ) -> SgxStatus;
    fn save_kek_manager(eid: EnclaveId) -> SgxStatus;
}

/// The key management manager
pub struct KekManagerProxy {
    /// sgx environment id, used to call enclave functions.\
    /// we use **a global sgx environment** to avoid creating a new enclave for each encryption/decryption
    sgx_environment_id: EnclaveId,
}
impl KekManagerProxy {
    pub fn new(enclave_path: impl AsRef<Path>, kek_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let global_sgx_environment = GLOBAL_SGX_KEK_MANAGE_ENV
            .get_or_try_init(|| SgxEnclave::create(enclave_path.as_ref(), true))?;
        let kek_path = kek_path.as_ref().to_str().unwrap();
        let eid = global_sgx_environment.eid();

        // RAII for `KEKManager`
        // we needn't to implement `Drop` for this struct,
        // because `KEKManager` implements `Drop` itself,
        // when this struct is dropped, `KEKManager` will be dropped first,
        // when `KEKManager` drops its `Drop` method will be called automatically.
        let init_kek_manager_status =
            unsafe { init_kek_manager(eid, kek_path.as_ptr(), kek_path.len()) };
        match init_kek_manager_status {
            SgxStatus::Success => (),
            _ => {
                return Err(anyhow::anyhow!(
                    "init kek manager failed with status: {:?}",
                    init_kek_manager_status
                ))
            }
        }

        Ok(Self {
            sgx_environment_id: eid,
        })
    }
}

impl KekManagerProxy {
    pub fn sgx_create_user_kek(
        &self,
        user_id: u32,
        user_password: impl AsRef<[u8]>,
    ) -> anyhow::Result<()> {
        let user_password = user_password.as_ref();
        let mut status = SgxStatus::Unexpected;
        unsafe {
            create_user_kek(
                self.sgx_environment_id,
                &mut status,
                user_id,
                user_password.as_ptr(),
                user_password.len(),
            )
        };
        match status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!(
                "create user kek failed with status: {:?}",
                status
            )),
        }
    }

    pub fn sgx_generate_random_wrapped_key(
        &self,
        user_id: u32,
        user_password: impl AsRef<[u8]>,
    ) -> anyhow::Result<[u8; 32]> {
        let user_password = user_password.as_ref();
        let mut wrapped_key = [0u8; 32];
        let mut status = SgxStatus::Unexpected;
        unsafe {
            generate_random_wrapped_key(
                self.sgx_environment_id,
                &mut status,
                user_id,
                user_password.as_ptr(),
                user_password.len(),
                wrapped_key.as_mut_ptr(),
                wrapped_key.len(),
            )
        };
        match status {
            SgxStatus::Success => Ok(wrapped_key),
            SgxStatus::InvalidParameter => Err(anyhow::anyhow!("invalid user id or password")),
            _ => Err(anyhow::anyhow!(
                "generate random wrapped key internal engine failed with status: {:?}",
                status
            )),
        }
    }

    pub fn sgx_check_user_password(&self, user_id: u32, user_password: impl AsRef<[u8]>) -> bool {
        let user_password = user_password.as_ref();
        let mut status = SgxStatus::Unexpected;
        unsafe {
            check_user_password_outside_sgx(
                self.sgx_environment_id,
                &mut status,
                user_id,
                user_password.as_ptr(),
                user_password.len(),
            )
        };
        matches!(status, SgxStatus::Success)
    }

    pub fn sgx_update_user_kek(
        &self,
        user_id: u32,
        old_user_password: impl AsRef<[u8]>,
        new_user_password: impl AsRef<[u8]>,
    ) -> anyhow::Result<()> {
        let old_user_password = old_user_password.as_ref();
        let new_user_password = new_user_password.as_ref();
        let mut status = SgxStatus::Unexpected;
        unsafe {
            update_user_kek(
                self.sgx_environment_id,
                &mut status,
                user_id,
                old_user_password.as_ptr(),
                old_user_password.len(),
                new_user_password.as_ptr(),
                new_user_password.len(),
            )
        };
        match status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!(
                "update user kek failed with status: {:?}",
                status
            )),
        }
    }
    /// save user kek to disk
    pub fn sgx_save_user_kek(&self) -> anyhow::Result<()> {
        let status = unsafe { save_kek_manager(self.sgx_environment_id) };
        match status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!(
                "save user kek failed with status: {:?}",
                status
            )),
        }
    }
}

#[cfg(test)]
extern "C" {
    fn clear_user_kek(eid: EnclaveId) -> SgxStatus;
}
#[cfg(test)]
impl KekManagerProxy {
    pub fn clear_user_kek(&self) -> anyhow::Result<()> {
        let status = unsafe { clear_user_kek(self.sgx_environment_id) };
        match status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!(
                "clear user kek failed with status: {:?}",
                status
            )),
        }
    }
}
impl Drop for KekManagerProxy {
    fn drop(&mut self) {
        // save user kek before drop
        self.sgx_save_user_kek().expect("save user kek failed");
    }
}
#[cfg(test)]
mod tests {
    extern "C" {
        fn run_kek_management_rust_api_tests(eid: EnclaveId) -> SgxStatus;
        fn run_kek_management_c_api_tests(eid: EnclaveId) -> SgxStatus;

    }
    use super::*;
    use crate::sgx_components::DEFAULT_ENCLAVE_PATH;
    #[test]
    fn sgx_kek_management_rust_api_tests() -> anyhow::Result<()> {
        //create an enclave
        let enclave = SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true)?;
        let test_driver_run_status = unsafe { run_kek_management_rust_api_tests(enclave.eid()) };
        match test_driver_run_status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!("test_failed")),
        }
    }

    #[test]
    fn sgx_kek_management_c_api_tests() -> anyhow::Result<()> {
        //create an enclave
        let enclave = SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true)?;
        let test_driver_run_status = unsafe { run_kek_management_c_api_tests(enclave.eid()) };
        match test_driver_run_status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!("test failed")),
        }
    }

    #[test]
    fn kek_management_wrapper_test() -> anyhow::Result<()> {
        let test_file = Path::new("/tmp/kek_wrapper_test");
        if test_file.exists() {
            std::fs::remove_file(test_file)?;
        }
        let user_id = 1;
        let kek_manager = KekManagerProxy::new(DEFAULT_ENCLAVE_PATH, test_file).unwrap();
        kek_manager.sgx_create_user_kek(user_id, "password")?;
        kek_manager.sgx_update_user_kek(user_id, "password", "new_password")?;
        drop(kek_manager);
        let key_manager = KekManagerProxy::new(DEFAULT_ENCLAVE_PATH, test_file).unwrap();
        assert!(key_manager
            .sgx_create_user_kek(user_id, "new_password")
            .is_err());
        Ok(())
    }
}
