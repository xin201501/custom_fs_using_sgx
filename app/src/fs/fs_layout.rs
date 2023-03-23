//! what does our filesystem look like in the memory

use crate::{
    fs::{Directory, FileKind, Inode},
    tde_cursor::TDECursor,
    utils::{self, traits::SerializeAndDigest},
};

use super::{superblock::SuperBlock, Group, DIRECT_POINTERS, INODE_SIZE, ROOT_INODE};
use anyhow::anyhow;
use memmap2::MmapMut;
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
const DIRECT_POINTERS_U64: u64 = DIRECT_POINTERS as u64;
/// it has the following layout:
/// - superblock
/// - block groups
#[derive(Debug, Default)]
pub struct MyFS {
    /// the superblock of this filesystem
    superblock: Option<SuperBlock>,
    /// data block groups of this filesystem
    block_groups: Option<Vec<Group>>,
    /// image file handle to operate underlying image file
    image_file_handle: Option<MmapMut>,
}
type Errno = i32;

impl MyFS {
    /// create a new filesystem instance
    /// # Params
    /// - `image_path`: the path of the image file,\
    /// something like `Block Device`,like **/dev/sda1**
    /// # Return
    /// an [anyhow::Result] type,\
    /// which contains a [MyFS] instance if the operation is successful
    pub fn new<P>(image_path: P, block_size: u32) -> anyhow::Result<Self>
    where
        P: AsRef<Path>,
    {
        // open the "device" for read and write
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(image_path.as_ref())?;

        // Safety
        // This method returns an error when the underlying system call fails,
        // which can happen for a variety of reasons,
        // such as when the file is not open with read and write permissions.
        // from https://docs.rs/memmap2/0.5.10/memmap2/struct.MmapMut.html
        let file_mmap_area = unsafe { MmapMut::map_mut(&file)? };
        let mut cursor = TDECursor::new(file_mmap_area, block_size as u64);

        // read superblock
        let superblock = SuperBlock::deserialize_from(&mut cursor)?;
        let block_groups = Group::deserialize_from(
            &mut cursor,
            superblock.inode_count,
            superblock.block_size,
            superblock.groups,
        )?;
        // restore the original FS state
        let mut fs = MyFS {
            superblock: Some(superblock),
            block_groups: Some(block_groups),
            image_file_handle: Some(cursor.into_inner()),
        };
        fs.create_root()?;
        Ok(fs)
    }

    /// create root directory "/"
    pub fn create_root(&mut self) -> anyhow::Result<()> {
        let first_group = self
            .groups_mut()
            .get_mut(0)
            .ok_or(anyhow!("can't find the first group"))?;
        // if already has root inode, do nothing
        if first_group.has_inode(ROOT_INODE as _) {
            return Ok(());
        }
        // block group does not have root inode, create it
        let mut inode = Inode::new(1, FileKind::Directory, self.superblock().block_size);
        inode.mode = libc::S_IFDIR as u16 | 0o777;
        inode.hard_links = 2;
        //create root directory,named as "/"
        let mut dir = Directory::default();
        dir.entries.insert(".".into(), ROOT_INODE);
        let index = self
            .allocate_inode()
            .ok_or_else(|| anyhow!("No space left for inodes"))?;
        // assert_eq!(index, ROOT_INODE);
        if index != ROOT_INODE {
            return Err(anyhow!("root inode index must be 1, not {index}"));
        }
        inode.add_block(
            self.allocate_data_block()
                .ok_or_else(|| anyhow!("No space left for data"))?,
            0,
        )?;
        self.save_inode(&mut inode, index)?;
        self.save_dir(dir, index)
    }
}
/// get [SuperBlock]、[Group] and [image_file_handle] of this filesystem
impl MyFS {
    #[inline]
    pub fn groups(&self) -> &[Group] {
        self.block_groups.as_ref().unwrap()
    }

    #[inline]
    fn groups_mut(&mut self) -> &mut [Group] {
        self.block_groups.as_mut().unwrap()
    }

    #[inline]
    pub fn superblock(&self) -> &SuperBlock {
        self.superblock.as_ref().unwrap()
    }

    #[inline]
    pub(crate) fn superblock_mut(&mut self) -> &mut SuperBlock {
        self.superblock.as_mut().unwrap()
    }

    #[inline]
    pub fn image_file_mmap(&self) -> &MmapMut {
        self.image_file_handle.as_ref().unwrap()
    }

    #[inline]
    pub(crate) fn image_file_mmap_mut(&mut self) -> &mut MmapMut {
        self.image_file_handle.as_mut().unwrap()
    }

    // #[inline]
    // pub(crate) fn take_image_file_cursor(&mut self) -> TDECursor<MmapMut> {
    //     self.image_file_handle.unwrap().into_inner()
    // }
}
/// [Inode] operations
impl MyFS {
    #[inline]
    pub(crate) fn save_inode(&mut self, inode: &mut Inode, index: u64) -> anyhow::Result<()> {
        let block_size = self.superblock().block_size;
        // self.superblock().wrapped_data_encryption_key,

        inode.block_size = block_size;
        let offset = self.inode_seek_position(index);
        // let file = OpenOptions::new()
        // .create(new)
        // .read(true)
        // .write(true)
        // .open("")
        // let image_file_mmap = self.image_file_mmap_mut().as_mut();
        let cursor = self.image_file_mmap_mut();
        let mut cursor = TDECursor::new(cursor, block_size as u64);
        // locate this inode's position
        cursor.seek(SeekFrom::Start(offset))?;
        inode.update_modified_at();

        inode.serialize_into(&mut cursor).map(|_size| ())?;
        anyhow::Ok(cursor.flush()?)
    }

    pub(crate) fn save_dir(&mut self, mut dir: Directory, index: u64) -> anyhow::Result<()> {
        let mut inode = self
            .find_inode(index)
            .map_err(|_| anyhow!("can't find inode with index: {index}!"))?;

        let serialized_dir = dir.serialize()?;
        inode.file_size = serialized_dir.len() as u64;
        self.save_inode(&mut inode, index)?;
        let data_block_index = inode
            .direct_blocks
            .first()
            .ok_or_else(|| anyhow!("inode {index} has no data block"))?;
        let offset = self.data_block_seek_position(*data_block_index as u64);

        let block_size = self.superblock().block_size;

        let cursor = self.image_file_mmap_mut();
        let mut cursor = TDECursor::new(cursor, block_size as u64);
        cursor.seek(SeekFrom::Start(offset))?;
        cursor.write_all(serialized_dir.as_slice())?;
        anyhow::Ok(cursor.flush()?)
    }

    #[inline]
    pub fn find_inode(&self, index: u64) -> Result<Inode, Errno> {
        // locate current inode's group and bitmap index pair
        let (group_index, _bitmap_index) = self.inode_offsets(index);
        if !self
            .groups()
            .get(group_index as usize)
            .ok_or(libc::ENOENT)?
            .has_inode(index as usize)
        {
            return Err(libc::ENOENT);
        }

        // find inode physical location
        let offset = self.inode_seek_position(index);
        let cursor = self.image_file_mmap();
        let block_size = self.superblock().block_size;
        let mut cursor = TDECursor::new(cursor, block_size as u64);
        cursor
            .seek(SeekFrom::Start(offset))
            .map_err(|_| libc::EIO)?;
        // recover the inode
        let inode = Inode::deserialize_from(&mut cursor).map_err(|_| libc::EIO)?;
        Ok(inode)
    }

    fn find_inode_from_path<P>(&self, path: P) -> Result<(Inode, u64), Errno>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        match path.parent() {
            // This is the root directory "/"
            None => Ok((self.find_inode(ROOT_INODE)?, ROOT_INODE)),
            // else
            Some(parent) => {
                let (parent, _) = self.find_dir(parent)?;
                let child_index = parent.entry(path.file_name().ok_or(libc::EINVAL)?);
                // if entry is found,get inode
                // else raise `no entry` error
                if let Some(child_index) = child_index {
                    let inode = self.find_inode(child_index)?;
                    Ok((inode, child_index))
                } else {
                    Err(libc::ENOENT)
                }
            }
        }
    }

    pub(crate) fn find_dir<P>(&self, path: P) -> Result<(Directory, u64), Errno>
    where
        P: AsRef<Path>,
    {
        // from root directory "/" down to the target directory
        let mut current_dir = self.find_dir_from_inode(ROOT_INODE)?;
        let mut index = ROOT_INODE;
        // skip things before "/"
        for c in path.as_ref().components().skip(1) {
            index = current_dir.entry(c).ok_or(libc::ENOENT)?;
            current_dir = self.find_dir_from_inode(index)?;
        }

        Ok((current_dir, index))
    }

    pub fn find_dir_from_inode(&self, index: u64) -> Result<Directory, Errno> {
        let inode = self.find_inode(index)?;
        if !inode.is_dir() {
            return Err(libc::ENOTDIR);
        }
        // TODO: support more blocks
        let block = inode.direct_blocks[0];
        let (group_index, _) = self.data_block_offsets(index);
        if !self
            .groups()
            .get(group_index as usize)
            .unwrap()
            .has_data_block(block as usize)
        {
            return Err(libc::ENOENT);
        }
        let SuperBlock { block_size, .. } = self.superblock();
        let cursor = self.image_file_mmap();
        let mut cursor = TDECursor::new(cursor, *block_size as u64);
        cursor
            .seek(SeekFrom::Start(self.data_block_seek_position(block as u64)))
            .map_err(|_| 4)?;
        // read in data blocks
        Directory::deserialize_from(&mut cursor).map_err(|_| 6)
    }
}

/// data block operations
impl MyFS {
    pub(crate) fn find_data_block(
        &mut self,
        inode: &mut Inode,
        offset: u64,
        read_only: bool,
    ) -> Result<(u32, u32), Errno> {
        let block_size = self.superblock().block_size as u64;
        let index = offset / block_size;

        let pointers_per_block = block_size / std::mem::size_of::<u32>() as u64;

        let block = if index < DIRECT_POINTERS_U64 {
            // index is in direct blocks
            inode.find_direct_block(index as usize)
        } else if index < (pointers_per_block + DIRECT_POINTERS_U64) {
            // index is in indirect blocks
            self.find_indirect(
                inode.indirect_block,
                index - DIRECT_POINTERS_U64,
                offset,
                pointers_per_block,
            )
            .map_err(|_| libc::EIO)?
        } else if index
            < (pointers_per_block * pointers_per_block // indirect block count
                + pointers_per_block
                + DIRECT_POINTERS_U64)
        {
            // index is in double indirect blocks
            self.find_indirect(
                inode.double_indirect_block,
                index - DIRECT_POINTERS_U64,
                offset,
                pointers_per_block,
            )
            .map_err(|_| libc::EIO)?
        } else {
            // index is out of range
            return Err(libc::ERANGE);
        };

        if block != 0 {
            return Ok((block, ((index + 1) * block_size - offset) as u32));
        }

        if read_only {
            return Err(libc::EINVAL);
        }

        let mut block = self.allocate_data_block().ok_or(libc::ENOSPC)?;
        if index < DIRECT_POINTERS_U64 {
            inode
                .add_block(block, index as usize)
                .map_err(|_| libc::ENOSPC)?;
        } else if index < (pointers_per_block + DIRECT_POINTERS_U64) {
            if inode.indirect_block == 0 {
                inode.indirect_block = block;
                self.write_data_to_data_block(&vec![0u8; block_size as usize], 0, block)
                    .map_err(|_| libc::EIO)?;
                block = self.allocate_data_block().ok_or(libc::ENOSPC)?;
            }

            self.save_indirect(
                inode.indirect_block,
                block,
                index - DIRECT_POINTERS_U64,
                pointers_per_block,
            )
            .map_err(|_| libc::EIO)?;
        } else if index
            < (pointers_per_block * pointers_per_block + pointers_per_block + DIRECT_POINTERS_U64)
        {
            if inode.double_indirect_block == 0 {
                inode.double_indirect_block = block;
                self.write_data_to_data_block(&vec![0u8; block_size as usize], 0, block)
                    .map_err(|_| libc::EIO)?;
                block = self.allocate_data_block().ok_or(libc::ENOSPC)?;
            }

            let indirect_offset = (index - DIRECT_POINTERS_U64) / pointers_per_block - 1;
            let indirect_block = match self
                .find_indirect(
                    inode.double_indirect_block,
                    indirect_offset,
                    0,
                    pointers_per_block,
                )
                .map_err(|_| libc::EIO)?
            {
                0 => {
                    let indirect_block = block;
                    self.save_indirect(
                        inode.double_indirect_block,
                        block,
                        indirect_offset,
                        pointers_per_block,
                    )
                    .map_err(|_| libc::EIO)?;
                    self.write_data_to_data_block(&vec![0u8; block_size as usize], 0, block)
                        .map_err(|_| libc::EIO)?;
                    block = self.allocate_data_block().ok_or(libc::ENOSPC)?;
                    indirect_block
                }
                indirect_block => indirect_block,
            };

            self.save_indirect(
                indirect_block,
                block,
                (index - DIRECT_POINTERS_U64) & (pointers_per_block - 1),
                pointers_per_block,
            )
            .map_err(|_| libc::EIO)?;
        } else {
            return Err(libc::ENOSPC);
        }

        Ok((block, block_size as u32))
    }

    fn find_indirect(
        &self,
        pointer: u32,
        index: u64,
        _offset: u64,
        pointers_per_block: u64,
    ) -> anyhow::Result<u32> {
        if pointer == 0 {
            return Ok(pointer);
        }

        let off = if index < pointers_per_block {
            index & (pointers_per_block - 1)
        } else {
            index / pointers_per_block - 1
        };

        let block = self.read_u32_from_data_block(off, pointer)?;

        if block == 0 || index < pointers_per_block {
            return Ok(block);
        }

        self.find_indirect(
            block,
            index & (pointers_per_block - 1),
            _offset,
            pointers_per_block,
        )
    }

    fn save_indirect(
        &mut self,
        pointer: u32,
        block: u32,
        index: u64,
        pointers_per_block: u64,
    ) -> anyhow::Result<()> {
        assert_ne!(pointer, 0);
        let offset = index & (pointers_per_block - 1);

        if index < pointers_per_block {
            self.write_data_to_data_block(&block.to_le_bytes(), offset * 4, pointer)
                .map(|_| ())
        } else {
            let indirect_offset = index / pointers_per_block - 1;
            let new_pointer = self.read_u32_from_data_block(indirect_offset, pointer)?;
            self.save_indirect(new_pointer, block, offset, pointers_per_block)
        }
    }

    // (group_block_index, bitmap_index),start at 1
    #[inline]
    fn inode_offsets(&self, index: u64) -> (u64, u64) {
        let inodes_per_group = self.superblock().block_size as u64 * 8;
        let inode_bg = (index - 1) / inodes_per_group;
        let bitmap_index = (index - 1) & (inodes_per_group - 1);
        (inode_bg, bitmap_index)
    }

    #[inline]
    fn inode_seek_position(&self, index: u64) -> u64 {
        let (group_index, bitmap_index) = self.inode_offsets(index);

        let SuperBlock { block_size, .. } = self.superblock();
        *block_size as u64 + // for `SuperBlock`
        group_index
            * utils::fs_size_calculator::block_group_size(*block_size)
            + 2 * (*block_size) as u64 // inode bitmap and block bitmap
            + bitmap_index * INODE_SIZE as u64
    }

    #[inline]
    fn data_block_offsets(&self, index: u64) -> (u64, u64) {
        let data_blocks_per_group = self.superblock().block_size as u64 * 8;
        let group_index = (index - 1) / data_blocks_per_group;
        let block_index = (index - 1) & (data_blocks_per_group - 1);

        (group_index, block_index)
    }

    #[inline]
    fn data_block_seek_position(&self, index: u64) -> u64 {
        let (group_index, block_index) = self.data_block_offsets(index);

        let SuperBlock { block_size, .. } = self.superblock();
        (*block_size) as u64 // superblock
            + group_index * utils::fs_size_calculator::block_group_size(*block_size) // block_group
            + 2 * (*block_size) as u64 // 2 block for inode bitmap and block bitmap
            + (*block_size) as u64 * 8 * INODE_SIZE as u64 //inode table
            + (*block_size) as u64 * block_index // data block
    }

    pub(crate) fn allocate_inode(&mut self) -> Option<u64> {
        // TODO: handle when group has run out of space
        let group_index = self.groups().iter().position(|g| g.free_inodes() > 0)?;
        self.superblock_mut().free_inodes -= 1;
        let group = self.groups_mut().get_mut(group_index).unwrap();

        let index = group.allocate_inode()?;
        Some(index as u64 + group_index as u64 * self.superblock().block_size as u64)
    }

    pub(crate) fn allocate_data_block(&mut self) -> Option<u32> {
        // TODO: handle when group has run out of space
        let group_index = self
            .groups()
            .iter()
            .position(|g| g.free_data_blocks() > 0)?;

        self.superblock_mut().free_blocks_count -= 1;
        let group = self.groups_mut().get_mut(group_index).unwrap();

        let index = group.allocate_data_block()?;
        Some(index as u32 + group_index as u32 * self.superblock().block_size)
    }

    #[inline]
    pub(crate) fn release_data_blocks(&mut self, blocks: &[u32]) {
        for block in blocks {
            let (group_index, block_index) = self.data_block_offsets(*block as u64);
            // TODO: release multiple blocks from the same group in a single call
            self.groups_mut()
                .get_mut(group_index as usize)
                .unwrap()
                .release_data_block(1 + block_index as usize);
        }
        self.superblock_mut().free_blocks_count += blocks.len() as u64;
    }

    #[inline]
    pub(crate) fn release_inode(&mut self, index: u64) {
        let (group_index, _) = self.inode_offsets(index);
        self.groups_mut()
            .get_mut(group_index as usize)
            .unwrap()
            .release_inode(index as usize);
        self.superblock_mut().free_inodes += 1;
    }

    pub(crate) fn release_indirect_block(&mut self, block: u32) -> anyhow::Result<()> {
        let blocks = self.read_indirect_block(block)?;
        self.release_data_blocks(&blocks);
        Ok(())
    }

    pub(crate) fn release_double_indirect_block(&mut self, block: u32) -> anyhow::Result<()> {
        let pointers_per_block = self.superblock().block_size as usize / 4;
        let indirect_blocks = self.read_indirect_block(block)?;
        let mut blocks = Vec::with_capacity(indirect_blocks.len() * pointers_per_block);
        for b in indirect_blocks.iter().filter(|x| **x != 0) {
            blocks.append(&mut self.read_indirect_block(*b)?);
        }

        self.release_data_blocks(&indirect_blocks);
        self.release_data_blocks(&blocks);

        Ok(())
    }
}
/// read and write data in the filesystem
impl MyFS {
    pub(crate) fn write_data_to_data_block(
        &mut self,
        data: &[u8],
        offset: u64,
        block_index: u32,
    ) -> anyhow::Result<usize> {
        let block_offset = self.data_block_seek_position(block_index as u64);
        let block_size = self.superblock().block_size;
        let cursor = self.image_file_mmap_mut();

        let mut cursor = TDECursor::new(cursor, block_size as u64);
        cursor.seek(SeekFrom::Start(block_offset + offset))?;
        Ok(cursor.write(data)?)
    }

    pub(crate) fn read_data_from_data_block(
        &self,
        data: &mut [u8],
        offset: u64,
        block_index: u32,
    ) -> anyhow::Result<usize> {
        let block_offset = self.data_block_seek_position(block_index as u64);
        let cursor = self.image_file_mmap();
        let mut cursor = TDECursor::new(cursor, self.superblock().block_size as u64);
        cursor.seek(SeekFrom::Start(block_offset + offset))?;

        cursor.read_exact(data)?;

        Ok(data.len())
    }

    #[inline]
    fn read_u32_from_data_block(&self, offset: u64, block_index: u32) -> anyhow::Result<u32> {
        let mut data = [0u8; 4];
        self.read_data_from_data_block(&mut data, offset * 4, block_index)?;
        Ok(u32::from_le_bytes(data))
    }

    fn read_indirect_block(&mut self, block: u32) -> anyhow::Result<Vec<u32>> {
        let pointers_per_block = self.superblock().block_size as usize / 4;
        let mut vec = Vec::with_capacity(pointers_per_block);
        for i in 0..pointers_per_block {
            let b = self.read_u32_from_data_block(i as u64, block)?;
            if b != 0 {
                vec.push(b);
            }
        }

        Ok(vec)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        mkfs::mkfs,
        sgx_components::kek_management::DEFAULT_KEK_MANAGER_PATH,
        utils::{
            init_test_environment::{init_test_environment, DEFAULT_KEY_MANAGER_PATH},
            time_util::TimeDurationStruct,
        },
    };

    use super::*;
    #[test]
    fn test_inode_offsets() {
        // blocks per group = 8
        let fs = MyFS {
            superblock: Some(SuperBlock::new(1024, 512, 3, 0, 0)),
            ..MyFS::default()
        };
        const DATA_BLOCKS_PER_GROUP_U32: u32 = 512 * 8;
        const DATA_BLOCKS_PER_GROUP_U64: u64 = DATA_BLOCKS_PER_GROUP_U32 as _;
        let (group_index, offset) = fs.inode_offsets(1);
        assert_eq!(group_index, 0);
        assert_eq!(offset, 0);

        let (group_index, offset) = fs.inode_offsets(DATA_BLOCKS_PER_GROUP_U64);
        assert_eq!(group_index, 0);
        assert_eq!(offset, DATA_BLOCKS_PER_GROUP_U64 - 1);

        let (group_index, offset) = fs.inode_offsets(DATA_BLOCKS_PER_GROUP_U64 + 1);
        assert_eq!(group_index, 1);
        assert_eq!(offset, 0);

        let (group_index, offset) = fs.inode_offsets(2 * DATA_BLOCKS_PER_GROUP_U64 - 1);
        assert_eq!(group_index, 1);
        assert_eq!(offset, DATA_BLOCKS_PER_GROUP_U64 - 2);
        let (group_index, offset) = fs.inode_offsets(2 * DATA_BLOCKS_PER_GROUP_U64 + 1);
        assert_eq!(group_index, 2);
        assert_eq!(offset, 0);
    }
    #[test]
    fn test_inode_seek_position() {
        let superblock = SuperBlock::new(1024, 1024, 3, 0, 0);
        let fs = MyFS {
            superblock: Some(superblock),
            ..Default::default()
        };
        let offset = fs.inode_seek_position(1);
        assert_eq!(3072, offset);

        let offset = fs.inode_seek_position(2);
        assert_eq!(3072 + INODE_SIZE as u64, offset);

        let offset = fs.inode_seek_position(8192);
        assert_eq!(3072 + 8191 * INODE_SIZE as u64, offset); // superblock + data bitmap + inode bitmap + 8191 inodes

        let offset = fs.inode_seek_position(8193);
        assert_eq!(
            3072 + 8192 * INODE_SIZE as u64 + 1024 * 1024 * 8 + 2048,
            offset
        ); // superblock + data bitmap + inode bitmap + inode table + data blocks + data bitmap + inode bitmap
    }
    #[test]
    fn test_file_metadata() {
        let file_size = 100_000_000;
        let block_size = 1024;
        let inode_count = 1024;
        let password = "123456";
        let tmp_file = Path::new("/tmp/test_metadata.img");
        if tmp_file.exists() {
            std::fs::remove_file(tmp_file).expect("remove tmp file failed");
        }
        init_test_environment(DEFAULT_KEK_MANAGER_PATH, DEFAULT_KEY_MANAGER_PATH, 4);

        mkfs(tmp_file, file_size, inode_count, block_size, password).expect("create fs failed");

        let fs = MyFS::new(tmp_file, block_size).expect("create in memory MyFS instance failed!");
        let (inode, inode_index) = fs
            .find_inode_from_path("/")
            .expect("find root directory failed!");

        assert_eq!(inode_index, ROOT_INODE);
        assert_eq!(inode.mode as u32, libc::S_IFDIR | 0o777);
        assert_eq!(inode.hard_links, 2);
        assert_ne!(inode.modified_at, Some(TimeDurationStruct::default()));
        assert_ne!(
            inode.metadata_changed_at,
            Some(TimeDurationStruct::default())
        );

        std::fs::remove_file(tmp_file).expect("test is passed,but remove temp file failed!")
    }
    #[test]
    fn test_find_dir() {
        let file_size = 100_000_000;
        let block_size = 2048;
        let inode_count = 3172;
        let password = "123456";
        let tmp_file = Path::new("/tmp/test_find_dir.img");
        if tmp_file.exists() {
            std::fs::remove_file(tmp_file).expect("remove temp file failed,test won't run");
        }

        init_test_environment(DEFAULT_KEK_MANAGER_PATH, DEFAULT_KEY_MANAGER_PATH, 8);

        mkfs(tmp_file, file_size, inode_count, block_size, password)
            .expect("create test fs failed!");

        let fs = MyFS::new(tmp_file, block_size).expect("create in memory fs instance failed!");
        assert!(fs.find_dir("/").is_ok());
        assert_eq!(fs.find_dir("/not-a-dir").err(), Some(libc::ENOENT));

        std::fs::remove_file(tmp_file).expect("test is passed,but remove temp file failed!")
    }
}
