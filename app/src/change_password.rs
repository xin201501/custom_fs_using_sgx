use std::ffi::OsStr;

use anyhow::Ok;

use crate::sgx_components::{
    kek_management::{KekManagerProxy, DEFAULT_KEK_MANAGER_PATH},
    DEFAULT_ENCLAVE_PATH,
};

pub fn change_user_password(user_name: impl AsRef<OsStr>) -> anyhow::Result<()> {
    let user_id = users::get_user_by_name(&user_name);
    match user_id {
        None => {
            anyhow::bail!(r#"user not found,please create a new user in OS first."#);
        }
        Some(user) => {
            let user_id = user.uid();
            let old_user_password =
                rpassword::prompt_password("Please input the old password for the user: ")?;
            let new_user_password =
                rpassword::prompt_password("Please input the new password for the user: ")?;
            let kek_manager_proxy =
                KekManagerProxy::new(DEFAULT_ENCLAVE_PATH, DEFAULT_KEK_MANAGER_PATH)?;
            kek_manager_proxy.sgx_update_user_kek(user_id, old_user_password, new_user_password)?;
            println!("update user password successfully.");
            Ok(())
        }
    }
}
