//! register our filesystem to `FUSE` and mount it
use fuser::MountOption;
use std::path::Path;

use crate::fs::MyFS;
pub fn mount<P>(image_path: P, mountpoint: P) -> anyhow::Result<()>
where
    P: AsRef<Path>,
{
    let fs = MyFS::new(image_path, 512, [1u8; 32])?;

    let opts = vec![
        MountOption::FSName("MyFS".to_string()),
        MountOption::DefaultPermissions,
        MountOption::AllowOther,
        MountOption::AutoUnmount,
    ];

    Ok(fuser::mount2(fs, mountpoint, &opts)?)
}
