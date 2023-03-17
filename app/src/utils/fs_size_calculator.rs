//! This module contains functions to calculate the size of differennt fs components

use crate::fs::INODE_SIZE;

/// calculate needed Inode Bitmap size
/// # Arguments
/// - `inode_count`: the number of inodes
/// # Return
/// the size of the Inode Bitmap
/// # Example
/// ```
/// use filesystem::utils::fs_size_calculator::bitmap_size;
/// let inode_count = 100;
/// let bitmap_size = bitmap_size(inode_count);
/// assert_eq!(bitmap_size, 13);
/// ```
pub const fn bitmap_size(element_count: u32) -> u64 {
    element_count.div_ceil(8) as u64
}

/// calculate needed Inode Table size
/// # Arguments
/// - `inode_count`: the number of inodes
/// # Return
/// the size of the Inode Table
/// # Example
/// ```
/// use filesystem::utils::fs_size_calculator::inode_table_size;
/// use filesystem::INODE_SIZE;
/// let block_size = 512;
/// let table_size = inode_table_size(block_size);
/// assert_eq!(table_size,512 * 8 * INODE_SIZE);
pub const fn inode_table_size(block_size: u32) -> u32 {
    block_size * 8 * INODE_SIZE
}

/// caculate block group size
/// # Arguments
/// - `blk_count`: the number of blocks
/// # Return
/// the size of a block group
/// # Example
/// ```
/// use filesystem::utils::fs_size_calculator::block_group_size;
/// use filesystem::INODE_SIZE;
/// let block_size = 512;
/// let group_size = block_group_size(block_size);
/// assert_eq!(group_size,2 * 512 + 512 * 8 * INODE_SIZE as u64 + 512 * 512 * 8);
pub const fn block_group_size(block_size: u32) -> u64 {
    block_size as u64 + // data bitmap
            block_size as u64 + // inode bitmap
            inode_table_size(block_size) as u64 +
            data_table_size(block_size) as u64
}
/// calculate data table size
/// # Arguments
/// - `blk_size`: the size of a block
/// # Return
/// the size of the data table
/// # Example
/// ```
/// use filesystem::utils::fs_size_calculator::data_table_size;
/// let block_size = 512;
/// let table_size = data_table_size(block_size);   
/// assert_eq!(table_size, 2 << 20);
pub const fn data_table_size(block_size: u32) -> u32 {
    block_size * block_size * 8
}
