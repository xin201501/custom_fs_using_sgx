//! create our filesystem
use crate::{
    fs::SuperBlock,
    sgx_components::{
        kek_management::{KekManagerProxy, DEFAULT_KEK_MANAGER_PATH},
        DEFAULT_ENCLAVE_PATH,
    },
    tde_cursor::TDECursor,
    utils,
};
use anyhow::{anyhow, Ok};
use byte_unit::{Byte, ByteUnit};
use memmap2::MmapMut;
use std::{
    fs::OpenOptions,
    io::{Seek, Write},
    path::Path,
};
use utils::traits::SerializeAndDigest;
/// create a new filesystem,given the path of the image file,image file size and block size,
/// # Params
/// - `image_file_path`: the path of the image file
/// - `file_size`: the size of the image file
/// - `inode_count`: the number of inodes
/// - `block_size`: the block size of the filesystem
///
/// # Return
/// an [anyhow::Result] type to indicate whether the operation is successful
pub fn mkfs<P>(
    image_file_path: P,
    file_size: u64,
    inode_count: u64,
    block_size: u32,
    password: impl AsRef<[u8]>,
) -> anyhow::Result<()>
where
    P: AsRef<Path>,
{
    // check if specified image_file_size is enough
    // if `file_size` < 2 blocks(for superblock) + a `block_group`'s size,return error
    let block_group_size = utils::fs_size_calculator::block_group_size(block_size);
    let space_needed = 2 * block_size as u64 + block_group_size;
    if file_size < space_needed {
        return Err(anyhow!(format!(
            "File size must be at least {} for block size {} and inode count {}",
            Byte::from_bytes(space_needed as _).get_appropriate_unit(true),
            Byte::from_bytes(block_size as _).get_adjusted_unit(ByteUnit::B),
            inode_count
        )));
    }

    // use `users` crate to get the uid and gid of this program
    let uid = users::get_effective_uid();
    let gid = users::get_effective_gid();
    let user_password = password.as_ref();
    let kekmanager_proxy = KekManagerProxy::new(DEFAULT_ENCLAVE_PATH, DEFAULT_KEK_MANAGER_PATH)?;
    kekmanager_proxy.sgx_create_user_kek(uid, user_password)?;
    // generate a random wrapped key for this filesystem
    let wrapped_key = kekmanager_proxy.sgx_generate_random_wrapped_key(uid, user_password)?;
    println!("generated user_kek :{wrapped_key:?}");
    // if file size is 1.3x block groups(for example),we will create 1 block group
    // and shrink the file size to fit 1x block group
    let groups = file_size.div_floor(block_group_size) as u32;

    let mut superblock = SuperBlock::new(inode_count, block_size, groups, uid, gid);
    // open image file and prepare to write fs components
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .truncate(true)
        .open(image_file_path)?;

    // align file size to block size
    let file_len = block_size as u64
        * (block_size as u64 + block_group_size * groups as u64).div_ceil(block_size as u64);
    // all other region are set to zero using `set_len` method
    file.set_len(file_len)?;

    let file_mmap_area = unsafe { MmapMut::map_mut(&file)? };
    let mut cursor = TDECursor::new(file_mmap_area, block_size as u64);
    // write superblock to the image file
    let zeros = vec![0u8; file_len as usize];
    cursor.write_all(&zeros)?;
    // reset cursor to zero
    cursor.rewind()?;
    superblock.serialize_into(&mut cursor)?;

    file.flush().expect("flush file content failed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fs::ROOT_INODE,
        fs::{FileKind, MyFS},
        utils::init_test_environment::{init_test_environment, DEFAULT_KEY_MANAGER_PATH},
    };
    use std::{path::PathBuf, str::FromStr};

    #[test]
    fn test_mkfs() {
        let tmp_file = PathBuf::from_str("/tmp/new_fs.img").unwrap();
        if tmp_file.exists() {
            std::fs::remove_file(&tmp_file).unwrap();
        }
        let inode_count = 1024;
        let block_size = 512;
        let password = "123456";
        let block_group_size = utils::fs_size_calculator::block_group_size(block_size);
        let file_size = 2 * block_size as u64 + block_group_size;

        init_test_environment(DEFAULT_KEK_MANAGER_PATH, DEFAULT_KEY_MANAGER_PATH, 50);

        mkfs(&tmp_file, file_size, inode_count, block_size, password).unwrap();
        let fs = MyFS::new(&tmp_file, 512).unwrap();

        // test if root inode "/" is created correctly
        let inode = fs.find_inode(ROOT_INODE).unwrap();
        assert_eq!(inode.mode as u32, libc::S_IFDIR | 0o777);
        assert_eq!(inode.hard_links, 2);
        assert_eq!(inode.file_kind, FileKind::Directory);

        // test if `first_block_group` has root("/") inode and its data block
        let first_block_group = fs.groups().get(0).unwrap();
        assert!(first_block_group.has_inode(ROOT_INODE as _));

        // test if block groups number is correct
        let correct_group_count = file_size.div_floor(block_group_size) as u32;
        assert_eq!(correct_group_count, fs.groups().len() as u32);

        // test if superblock is created correctly
        let superblock = fs.superblock();
        assert_eq!(superblock.groups, correct_group_count);
        assert_eq!(superblock.free_inodes, inode_count - 1);
        assert_eq!(
            superblock.free_blocks_count,
            superblock.block_size as u64 * 8 * correct_group_count as u64 - 1
        );

        // remove test file
        std::fs::remove_file(&tmp_file).unwrap()
    }
}
