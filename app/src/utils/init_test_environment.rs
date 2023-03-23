use std::path::Path;

use crate::sgx_components::{kek_management::KekManagerProxy, DEFAULT_ENCLAVE_PATH};

pub const DEFAULT_KEY_MANAGER_PATH: &str = "/tmp/key_manager";

#[cfg(test)]
pub fn init_test_environment<T>(kek_file_path: T, key_file_path: T, test_uid: u32)
where
    T: AsRef<Path>,
{
    let kek_file_path = kek_file_path.as_ref();
    let key_file_path = key_file_path.as_ref();
    if key_file_path.exists() {
        std::fs::remove_file(key_file_path).expect("Failed to remove key file");
    }
    let kek_manager_proxy = KekManagerProxy::new(DEFAULT_ENCLAVE_PATH, kek_file_path)
        .expect("Failed to create kek manager");
    kek_manager_proxy
        .clear_user_kek()
        .expect("Failed to clear user kek");

    let test_user_password = "123456";
    kek_manager_proxy
        .sgx_create_user_kek(test_uid, test_user_password)
        .expect("Failed to create user kek");
    kek_manager_proxy
        .sgx_save_user_kek()
        .expect("Failed to save user kek");
    eprintln!("init test environment done");
}
