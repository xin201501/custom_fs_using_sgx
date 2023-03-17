use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::{io::Cursor, time::UNIX_EPOCH};

use crate::utils::{
    self,
    time_util::TimeDurationStruct,
    traits::{DigestInSelf, SerializeAndDigest},
};

use super::{filekind::FileKind, DIRECT_POINTERS};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Inode {
    pub block_size: u32,
    pub inode_number: u64,
    pub open_file_handles: u64,
    pub file_size: u64,
    pub mode: u16,
    pub hard_links: u32,
    pub user_id: libc::uid_t,
    pub group_id: libc::gid_t,
    pub block_count: u32,
    pub file_kind: FileKind,
    pub created_at: TimeDurationStruct,
    pub accessed_at: Option<TimeDurationStruct>,
    pub modified_at: Option<TimeDurationStruct>,
    pub metadata_changed_at: Option<TimeDurationStruct>,
    pub direct_blocks: [u32; DIRECT_POINTERS as usize],
    pub indirect_block: u32,
    pub double_indirect_block: u32,
    pub digest: [u8; 32],
}

/// Convert [Inode] to [FileAttr](fuser::FileAttr)
impl From<Inode> for fuser::FileAttr {
    fn from(attrs: Inode) -> Self {
        fuser::FileAttr {
            ino: attrs.inode_number,
            size: attrs.file_size,
            blocks: attrs.block_count as u64,
            atime: {
                attrs
                    .accessed_at
                    .map_or(UNIX_EPOCH, |accessed_at| accessed_at.into())
            },
            mtime: {
                attrs
                    .modified_at
                    .map_or(UNIX_EPOCH, |accessed_at| accessed_at.into())
            },
            ctime: {
                attrs
                    .metadata_changed_at
                    .map_or(UNIX_EPOCH, |accessed_at| accessed_at.into())
            },
            crtime: UNIX_EPOCH,
            kind: attrs.file_kind.into(),
            perm: attrs.mode,
            nlink: attrs.hard_links,
            uid: attrs.user_id,
            gid: attrs.group_id,
            rdev: 0,
            blksize: attrs.block_size,
            flags: 0,
        }
    }
}

/// This block is about digest and verify digest
impl DigestInSelf for Inode {
    fn digest(&mut self) {
        self.digest = [0u8; 32];
        self.digest = utils::digest::digest(&self).expect("calculate digest failed");
    }

    fn verify_digest(&mut self) -> bool {
        let current_digest = self.digest;
        self.digest = [0u8; 32];
        let ok = current_digest == utils::digest::digest(&self).expect("calculate digest failed");
        self.digest = current_digest;
        ok
    }
}
// This block is about serialization and deserialization
impl SerializeAndDigest for Inode {}

impl Inode {
    pub fn new(index: u64, file_kind: impl Into<FileKind>, block_size: u32) -> Self {
        let now = utils::time_util::now();
        // inode.created_at = now;
        // inode.file_kind
        // inode.accessed_at = Some(now);
        // inode.modified_at = Some(now);
        // inode.changed_at = Some(now);
        // inode.hard_links = 1;
        // inode

        Inode {
            inode_number: index,
            hard_links: 1,
            file_kind: file_kind.into(),
            created_at: now,
            accessed_at: Some(now),
            modified_at: Some(now),
            metadata_changed_at: Some(now),
            block_size,
            // don't calculate digest and other fields now
            ..Inode::default()
        }
    }
}

/// This block is about file metadata operations
impl Inode {
    pub fn is_regular_file(&self) -> bool {
        (self.mode & libc::S_IFREG as u16) != 0 && self.file_kind == FileKind::RegularFile
    }

    pub fn is_dir(&self) -> bool {
        (self.mode & libc::S_IFDIR as u16) != 0 && self.file_kind == FileKind::Directory
    }

    pub fn is_symlink(&self) -> bool {
        (self.mode & libc::S_IFLNK as u16) != 0 && self.file_kind == FileKind::SymbolicLink
    }

    pub fn update_modified_at(&mut self) {
        let now = utils::time_util::now();
        self.metadata_changed_at = Some(now);
        self.modified_at = Some(now);
    }

    pub fn update_accessed_at(&mut self) {
        self.accessed_at = Some(utils::time_util::now());
    }
}

/// This block is about file operations
/// Block SIZE fixed to 512 bytes issue has been fixed
impl Inode {
    pub fn direct_blocks(&self) -> Vec<u32> {
        self.direct_blocks
            .iter()
            .filter_map(|x| if *x != 0 { Some(*x) } else { None })
            .collect()
    }

    pub fn truncate(&mut self) -> Vec<u32> {
        self.update_modified_at();
        self.file_size = 0;
        self.block_count = 0;
        let blocks = self.direct_blocks();
        self.direct_blocks = [0u32; DIRECT_POINTERS as usize];
        blocks
    }

    pub fn find_direct_block(&self, index: usize) -> u32 {
        self.direct_blocks[index]
    }

    pub fn add_block(&mut self, block: u32, index: usize) -> anyhow::Result<()> {
        if index >= self.direct_blocks.len() {
            Err(anyhow!("No space in direct blocks"))
        } else {
            self.direct_blocks[index] = block;
            Ok(())
        }
    }

    pub fn adjust_size(&mut self, len: u64) {
        self.file_size = self.file_size.max(len);
        self.block_count = self.file_size as u32 / self.block_size + 1;
    }

    pub fn increment_size(&mut self, len: u64) {
        self.file_size += len;
        self.block_count = self.file_size as u32 / self.block_size + 1;
    }
}

impl Inode {
    /// Get the size of the inode in memory
    /// #Example
    /// ```
    /// use filesystem::Inode;
    /// let size = Inode::inode_size_in_memory();
    /// assert_eq!(size, 224);
    /// ```
    pub const fn inode_size_in_memory() -> usize {
        std::mem::size_of::<Inode>()
    }
    /// Get the size of the inode in disk
    /// #Example
    /// ```
    /// use filesystem::Inode;
    /// let size = Inode::inode_size_in_disk();
    /// assert_eq!(size, 153);
    /// ```
    pub fn inode_size_in_disk() -> usize {
        let mut inode = Inode::default();
        let mut serialized_inode = Vec::new();
        let mut cursor = Cursor::new(&mut serialized_inode);
        inode
            .serialize_into(&mut cursor)
            .expect("serialize inode failed");
        serialized_inode.len()
    }
}
