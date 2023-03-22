use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::utils::{
    digest,
    time_util::{self, *},
    traits::{DigestInSelf, SerializeAndDigest},
};

use super::{FILE_IN_INODE_DIRECTLY_SIZE, FS_MAGIC};

type InodeCountType = u64;
type BlockCountType = u64;
/// The superblock of this filesystem
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Encode, Decode)]
pub struct SuperBlock {
    /// magic number
    pub magic: u32,
    /// data block size
    pub block_size: u32,
    pub created_at: TimeDurationStruct,
    pub modified_at: Option<TimeDurationStruct>,
    pub last_mounted_at: Option<TimeDurationStruct>,
    /// data block count, if use extent it's not needed
    pub block_count: BlockCountType,
    pub free_blocks_count: BlockCountType,
    pub inode_count: InodeCountType,
    pub inode_file_contents_size: u8,
    pub free_inodes: InodeCountType,
    pub groups: u32,
    pub data_blocks_per_group: u32,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    /// to verify the integrity of this superblock
    /// intend to use a fast secure hash function,like [blake3]
    pub digest: [u8; 32],
}
impl SuperBlock {
    pub fn new(inode_count: u64, block_size: u32, groups: u32, uid: u32, gid: u32) -> Self {
        let total_block_count = block_size as u64 * 8 * groups as u64;
        let now = time_util::now();
        let mut superblock = Self {
            inode_count,
            block_size,
            groups,
            uid,
            gid,
            magic: FS_MAGIC,
            created_at: now,
            modified_at: None,
            last_mounted_at: None,
            free_inodes: inode_count,
            inode_file_contents_size: FILE_IN_INODE_DIRECTLY_SIZE,
            block_count: total_block_count,
            free_blocks_count: total_block_count,
            data_blocks_per_group: block_size * 8, // 1 byte has 8 bits to store block index
            digest: [0u8; 32],
        };
        superblock.digest();
        superblock
    }
}
impl SuperBlock {
    pub fn update_last_mounted_at(&mut self) {
        self.last_mounted_at = Some(time_util::now());
    }

    pub fn update_modified_at(&mut self) {
        self.modified_at = Some(time_util::now());
    }
}

// /// change master key
// impl SuperBlock {
//     pub fn change_data_encryption_key(&mut self, new_key: [u8; 32]) {
//         self.wrapped_data_encryption_key = new_key;
//         self.update_modified_at();
//         self.digest();
//     }
// }
impl DigestInSelf for SuperBlock {
    fn digest(&mut self) {
        self.digest = [0u8; 32];
        self.digest = digest::digest(self).expect("calculate digest failed");
    }

    fn verify_digest(&mut self) -> bool {
        // get digest from itself
        let digest = self.digest;
        // clear the digest from struct
        self.digest = [0u8; 32];
        // calulate the digest
        let digest2 = digest::digest(self).expect("calculate digest failed");
        // verify
        let ok = digest == digest2;
        // store newest digest to itself
        self.digest = digest2;
        // return verify result
        ok
    }
}

impl SerializeAndDigest for SuperBlock {}
