use std::io::{Read, Seek, SeekFrom, Write};

use anyhow::anyhow;
use bitvec::prelude::*;

use crate::utils::*;

#[derive(Debug, Default)]
pub struct Group {
    pub data_bitmap: BitVec<u8, Lsb0>,
    pub inode_bitmap: BitVec<u8, Lsb0>,
    next_inode: Option<usize>,
    next_data_block: Option<usize>,
}
/// for serialize and deserialize
impl Group {
    pub fn serialize_into<W>(mut w: W, block_size: u32, groups: &[Group]) -> anyhow::Result<()>
    where
        W: Write + Seek,
    {
        if groups.is_empty() {
            return Err(anyhow!("no group to serialize"));
        }
        let first_group = groups.first().ok_or(anyhow!(
            "unable to get the first group,can't fetch group metadata!"
        ))?;
        let _block_count = first_group.data_bitmap.len();
        // let inode_count = first_group.inode_bitmap.len();
        for (idx, g) in groups.iter().enumerate() {
            let offset = block_size as u64 + // for `SuperBlock`
             fs_size_calculator::block_group_size(
                block_size,
            ) * idx as u64;
            w.seek(SeekFrom::Start(offset))?;
            w.write_all(g.inode_bitmap.as_raw_slice())?;
            w.write_all(g.data_bitmap.as_raw_slice())?;
        }

        Ok(())
    }

    pub fn deserialize_from<R>(
        mut r: R,
        _inode_count: u64,
        block_size: u32,
        group_count: u32,
    ) -> anyhow::Result<Vec<Group>>
    where
        R: Read + Seek,
    {
        let mut groups = Vec::with_capacity(group_count as usize);
        let mut buf = vec![0; block_size as usize];

        for idx in 0..group_count {
            let offset = block_size as u64 + // for `SuperBlock`
            fs_size_calculator::block_group_size(block_size)
                * idx as u64;
            r.seek(SeekFrom::Start(offset))?;
            r.read_exact(&mut buf)?;
            let inode_bitmap = BitVec::<u8, Lsb0>::from_slice(&buf);
            r.read_exact(&mut buf)?;
            let data_bitmap = BitVec::<u8, Lsb0>::from_slice(&buf);
            groups.push(Group::new(inode_bitmap, data_bitmap));
        }

        Ok(groups)
    }
}
impl Group {
    pub fn new(inode_bitmap: BitVec<u8, Lsb0>, data_bitmap: BitVec<u8, Lsb0>) -> Self {
        let mut group = Group {
            inode_bitmap,
            data_bitmap,
            ..Default::default()
        };

        group.next_data_block = group.next_free_data_block();
        group.next_inode = group.next_free_inode();

        group
    }
}
/// for inode and data block allocation
impl Group {
    /// check if inode exists
    /// # Params
    /// - `i`: inode index,start at 1
    pub fn has_inode(&self, i: usize) -> bool {
        self.inode_bitmap.get(i - 1).as_deref().unwrap_or(&false) == &true
    }

    /// check if data block exists
    /// # Params
    /// - `i`: data block index,start at 1
    pub fn has_data_block(&self, i: usize) -> bool {
        self.data_bitmap.get(i - 1).as_deref().unwrap_or(&false) == &true
    }

    /// calculate the number of free inodes
    pub fn free_inodes(&self) -> usize {
        self.inode_bitmap.count_zeros()
    }

    /// calculate the number of free data blocks
    pub fn free_data_blocks(&self) -> usize {
        self.data_bitmap.count_zeros()
    }

    /// allocate a free inode
    pub fn allocate_inode(&mut self) -> Option<usize> {
        self.next_inode.map(|index| {
            self.bitmap_ocuupy_inode(index);
            self.next_inode = self.next_free_inode();
            index
        })
    }

    /// allocate a free data block
    pub fn allocate_data_block(&mut self) -> Option<usize> {
        self.next_data_block.map(|index| {
            self.bitmap_occupy_data_block(index);
            self.next_data_block = self.next_free_data_block();
            index
        })
    }

    /// release data block
    /// # Params
    /// - `index`: data block index,start at 1
    pub fn release_data_block(&mut self, index: usize) {
        self.data_bitmap.set(index - 1, false);
        self.next_data_block = self.next_free_data_block();
    }

    /// release inode
    /// # Params
    /// - `index`: inode index,start at 1
    pub fn release_inode(&mut self, index: usize) {
        self.inode_bitmap.set(index - 1, false);
        self.next_inode = self.next_free_inode();
    }

    fn bitmap_ocuupy_inode(&mut self, i: usize) {
        self.inode_bitmap.set(i - 1, true);
    }

    fn bitmap_occupy_data_block(&mut self, i: usize) {
        self.data_bitmap.set(i - 1, true);
    }

    // next free data block index,index start at 1
    fn next_free_data_block(&self) -> Option<usize> {
        // self.data_bitmap.iter()
        // .position(|bit| !*bit)
        // .map(|p| p + 1);
        self.data_bitmap.first_zero().map(|p| p + 1)
    }

    // next free inode index,index start at 1
    fn next_free_inode(&self) -> Option<usize> {
        // self.inode_bitmap
        //     .iter()
        //     .position(|bit| !*bit)
        //     .map(|p| p + 1)
        self.inode_bitmap.first_zero().map(|p| p + 1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    // test `has_inode`
    #[test]
    fn test_has_inode() {
        let mut inode_bitmap = BitVec::<u8, Lsb0>::with_capacity(10);
        for _ in 0..10 {
            inode_bitmap.push(true);
        }
        let block_datamap = BitVec::<u8, Lsb0>::new();
        let group = super::Group::new(inode_bitmap, block_datamap);
        assert!(group.has_inode(1));
        assert!(group.has_inode(10));
        assert!(!group.has_inode(11));
    }

    // test `has_data_block`
    #[test]
    fn test_has_data_block() {
        let inode_bitmap = BitVec::<u8, Lsb0>::new();
        let mut block_datamap = BitVec::<u8, Lsb0>::with_capacity(10);
        for _ in 0..10 {
            block_datamap.push(true);
        }
        let group = super::Group::new(inode_bitmap, block_datamap);
        assert!(group.has_data_block(1));
        assert!(group.has_data_block(10));
        assert!(!group.has_data_block(11));
    }

    // test [next_free_inode]
    #[test]
    fn test_next_free_inode() {
        // test if free space is at the beginning
        let mut inode_bitmap1 = BitVec::<u8, Lsb0>::with_capacity(10);
        inode_bitmap1.push(false);
        for _ in 0..15 {
            inode_bitmap1.push(true);
        }

        let block_datamap1 = BitVec::<u8, Lsb0>::new();
        let group1 = super::Group::new(inode_bitmap1, block_datamap1);

        assert_eq!(group1.next_free_inode(), Some(1));
        // test if free space is in the middle
        let mut inode_bitmap2 = BitVec::<u8, Lsb0>::with_capacity(15);
        for _ in 0..15 {
            inode_bitmap2.push(true);
        }
        inode_bitmap2.set(6, false);
        let block_datamap2 = BitVec::<u8, Lsb0>::new();
        let group1 = super::Group::new(inode_bitmap2, block_datamap2);
        assert_eq!(group1.next_free_inode(), Some(7));

        // test if free space is at the end
        let mut inode_bitmap3 = BitVec::<u8, Lsb0>::with_capacity(15);
        for _ in 0..15 {
            inode_bitmap3.push(true);
        }
        inode_bitmap3.set(14, false);
        let block_datamap3 = BitVec::<u8, Lsb0>::new();
        let group1 = super::Group::new(inode_bitmap3, block_datamap3);
        assert_eq!(group1.next_free_inode(), Some(15));
    }
    // test free data block
    #[test]
    fn test_next_free_data_block() {
        // test if free space is at the beginning
        let mut block_datamap1 = BitVec::<u8, Lsb0>::with_capacity(15);
        block_datamap1.push(false);
        for _ in 0..15 {
            block_datamap1.push(true);
        }

        let inode_bitmap1 = BitVec::<u8, Lsb0>::new();
        let group1 = super::Group::new(inode_bitmap1, block_datamap1);

        assert_eq!(group1.next_free_data_block(), Some(1));
        // test if free space is in the middle
        let mut block_datamap2 = BitVec::<u8, Lsb0>::with_capacity(15);
        for _ in 0..15 {
            block_datamap2.push(true);
        }
        block_datamap2.set(9, false);
        let inode_bitmap2 = BitVec::<u8, Lsb0>::new();
        let group1 = super::Group::new(inode_bitmap2, block_datamap2);
        assert_eq!(group1.next_free_data_block(), Some(10));

        // test if free space is at the end
        let mut block_datamap3 = BitVec::<u8, Lsb0>::with_capacity(15);
        for _ in 0..15 {
            block_datamap3.push(true);
        }
        block_datamap3.set(14, false);
        let inode_bitmap3 = BitVec::<u8, Lsb0>::new();
        let group1 = super::Group::new(inode_bitmap3, block_datamap3);
        assert_eq!(group1.next_free_data_block(), Some(15));
    }

    // test allocate inode
    #[test]
    fn test_allocate_inode() {
        // test if free space is at the beginning
        let mut inode_bitmap1 = BitVec::<u8, Lsb0>::with_capacity(15);
        inode_bitmap1.push(false);
        for _ in 0..15 {
            inode_bitmap1.push(true);
        }

        let block_datamap1 = BitVec::<u8, Lsb0>::new();
        let mut group1 = super::Group::new(inode_bitmap1, block_datamap1);

        assert_eq!(group1.allocate_inode(), Some(1));
        assert!(group1.inode_bitmap[0]); // The first block is allocated and occupied
                                         // test if free space is in the middle
        let mut inode_bitmap2 = BitVec::<u8, Lsb0>::with_capacity(15);
        for _ in 0..15 {
            inode_bitmap2.push(true);
        }
        inode_bitmap2.set(9, false);
        let block_datamap2 = BitVec::<u8, Lsb0>::new();
        let mut group1 = super::Group::new(inode_bitmap2, block_datamap2);
        assert_eq!(group1.allocate_inode(), Some(10));
        assert!(group1.inode_bitmap[9]); // The 10th block is allocated and occupied

        // test if free space is at the end
        let mut inode_bitmap3 = BitVec::<u8, Lsb0>::with_capacity(15);
        for _ in 0..15 {
            inode_bitmap3.push(true);
        }
        inode_bitmap3.set(14, false);
        let block_datamap3 = BitVec::<u8, Lsb0>::new();
        let mut group1 = super::Group::new(inode_bitmap3, block_datamap3);
        assert_eq!(group1.allocate_inode(), Some(15));
        assert!(group1.inode_bitmap[14]); // The last(15th) block is allocated and occupied
    }
    // test allocate data block
    #[test]
    fn test_allocate_data_block() {
        // test if free space is at the beginning
        let mut block_datamap1 = BitVec::<u8, Lsb0>::with_capacity(15);
        block_datamap1.push(false);
        for _ in 0..15 {
            block_datamap1.push(true);
        }

        let inode_bitmap1 = BitVec::<u8, Lsb0>::new();
        let mut group1 = super::Group::new(inode_bitmap1, block_datamap1);

        assert_eq!(group1.allocate_data_block(), Some(1));
        assert!(group1.data_bitmap[0]); // The first block is allocated and occupied
                                        // test if free space is in the middle
        let mut block_datamap2 = BitVec::<u8, Lsb0>::with_capacity(15);
        for _ in 0..15 {
            block_datamap2.push(true);
        }
        block_datamap2.set(9, false);
        let inode_bitmap2 = BitVec::<u8, Lsb0>::new();
        let mut group1 = super::Group::new(inode_bitmap2, block_datamap2);
        assert_eq!(group1.allocate_data_block(), Some(10));
        assert!(group1.data_bitmap[9]); // The 10th block is allocated and occupied

        // test if free space is at the end
        let mut block_datamap3 = BitVec::<u8, Lsb0>::with_capacity(15);
        for _ in 0..15 {
            block_datamap3.push(true);
        }
        block_datamap3.set(14, false);
        let inode_bitmap3 = BitVec::<u8, Lsb0>::new();
        let mut group1 = super::Group::new(inode_bitmap3, block_datamap3);
        assert_eq!(group1.allocate_data_block(), Some(15));
        assert!(group1.data_bitmap[14]); // The last(15th) block is allocated and occupied
    }
}
