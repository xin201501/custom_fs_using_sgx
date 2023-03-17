//! our custom filesystem
pub mod block_group;
pub mod filekind;
pub mod fs_layout;
pub mod inode;
pub mod superblock;
pub mod xattr;
// mod traits;
mod directory;
mod fs_api_impl;
pub(crate) use block_group::*;
pub(crate) use directory::*;
pub(crate) use filekind::*;
pub(crate) use fs_layout::*;
pub use inode::*;
pub(crate) use superblock::*;

const FS_MAGIC: u32 = 0x1324a;
pub const ROOT_INODE: u64 = 1;
pub const INODE_SIZE: u32 = 256;
const FILE_IN_INODE_DIRECTLY_SIZE: u8 = 16;
const DIRECT_POINTERS: u8 = 12;
