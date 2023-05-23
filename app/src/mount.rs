//! register our filesystem to `FUSE` and mount it
use fuser::MountOption;
use std::path::Path;

use crate::{
    fs::MyFS,
    sgx_components::{
        kek_management::{KekManagerProxy, DEFAULT_KEK_MANAGER_PATH},
        DEFAULT_ENCLAVE_PATH,
    },
};
pub fn mount<P>(image_path: P, mountpoint: P, password: impl AsRef<[u8]>) -> anyhow::Result<()>
where
    P: AsRef<Path>,
{
    // check if password is correct
    let key_manager = KekManagerProxy::new(DEFAULT_ENCLAVE_PATH, DEFAULT_KEK_MANAGER_PATH)?;
    let user_id = users::get_effective_uid();
    if !key_manager.sgx_check_user_password(user_id, password) {
        return Err(anyhow::anyhow!("password is incorrect"));
    }
    // end check

    println!("user password is correct!");
    let fs = MyFS::new(image_path, 512)?;

    let opts = vec![
        MountOption::FSName("MyFS".to_string()),
        MountOption::DefaultPermissions,
        // MountOption::AllowOther,
        // MountOption::AutoUnmount,
    ];

    Ok(fuser::mount2(fs, mountpoint, &opts)?)
}
