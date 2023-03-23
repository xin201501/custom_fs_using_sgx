//! a cursor that can be used to read and write data from a given buffer,
//! and encrypt/decrypt the data transparently using [aes],in [xts_mode].
use std::io::Cursor;
use std::io::Seek;
use std::io::{ErrorKind, IoSlice, IoSliceMut, SeekFrom, Write};

use crate::sgx_components::encryption::SGXEncryptionManager;
use crate::sgx_components::DEFAULT_ENCLAVE_PATH;
/// cursor struct
#[derive(Debug, Default)]
pub struct TDECursor<T> {
    inner: T,
    pos: u64,
    block_size: u64,
}
impl<T> TDECursor<T> {
    /// creates a new TDECursor with the [block_size] and [given key]
    pub fn new(inner: T, block_size: u64) -> Self {
        Self {
            inner,
            pos: 0,
            block_size,
        }
    }
    /// get underlying buffer
    pub fn into_inner(self) -> T {
        self.inner
    }
    /// get read only reference to underlying buffer
    pub const fn get_ref(&self) -> &T {
        &self.inner
    }
    /// get mutable reference to underlying buffer
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
    /// get the current position of the cursor
    pub const fn position(&self) -> u64 {
        self.pos
    }
    /// set the current position of the cursor
    pub fn set_position(&mut self, pos: u64) {
        self.pos = pos;
    }
}

impl<T> TDECursor<T>
where
    T: AsRef<[u8]>,
{
    /// Ref: https://doc.rust-lang.org/std/io/struct.Cursor.html#method.remaining_slice
    /// Returns the remaining slice.
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(cursor_remaining)]
    /// use filesystem::tde_cursor::TDECursor;
    ///
    /// let mut buff = TDECursor::new(vec![1, 2, 3, 4, 5],1);
    ///
    /// assert_eq!(buff.remaining_slice(), &[1, 2, 3, 4, 5]);
    ///
    /// buff.set_position(2);
    /// assert_eq!(buff.remaining_slice(), &[3, 4, 5]);
    ///
    /// buff.set_position(4);
    /// assert_eq!(buff.remaining_slice(), &[5]);
    ///
    /// buff.set_position(6);
    /// assert_eq!(buff.remaining_slice(), &[]);
    /// ```
    pub fn remaining_slice(&self) -> &[u8] {
        let len = self.pos.min(self.inner.as_ref().len() as u64);
        &self.inner.as_ref()[(len as usize)..]
    }

    /// Ref: https://doc.rust-lang.org/std/io/struct.Cursor.html#method.is_empty
    /// Returns `true` if the remaining slice is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(cursor_remaining)]
    /// use filesystem::tde_cursor::TDECursor;
    ///
    /// let mut buff = TDECursor::new(vec![1, 2, 3, 4, 5],1);
    ///
    /// buff.set_position(2);
    /// assert!(!buff.is_empty());
    ///
    /// buff.set_position(5);
    /// assert!(buff.is_empty());
    ///
    /// buff.set_position(10);
    /// assert!(buff.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.pos >= self.inner.as_ref().len() as u64
    }
}

impl<T> Clone for TDECursor<T>
where
    T: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            pos: self.pos,
            block_size: self.block_size,
        }
    }

    #[inline]
    fn clone_from(&mut self, other: &Self) {
        self.inner.clone_from(&other.inner);
        self.pos = other.pos;
        self.block_size = other.block_size;
    }
}

impl<T> std::io::Seek for TDECursor<T>
where
    T: AsRef<[u8]>,
{
    fn seek(&mut self, style: SeekFrom) -> std::io::Result<u64> {
        let (base_pos, offset) = match style {
            SeekFrom::Start(n) => {
                self.pos = n;
                return Ok(n);
            }
            SeekFrom::End(n) => (self.inner.as_ref().len() as u64, n),
            SeekFrom::Current(n) => (self.pos, n),
        };
        match base_pos.checked_add_signed(offset) {
            Some(n) => {
                self.pos = n;
                Ok(self.pos)
            }
            None => Err(ErrorKind::InvalidInput.into()),
        }
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.pos)
    }
}

impl<T> std::io::Read for TDECursor<T>
where
    T: AsRef<[u8]>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len();
        // ---------------to decrypt the data -------------
        let pos = std::cmp::min(self.pos, self.inner.as_ref().len() as u64);
        let cipher_text_block_start_offset = self.block_size * (pos / self.block_size);
        let cipher_text_block_end_offset =
            (pos + buf.len() as u64).div_ceil(self.block_size) * self.block_size;

        let related_cipher_text_area = &self.inner.as_ref()
            [cipher_text_block_start_offset as usize..cipher_text_block_end_offset as usize];
        // dbg!(cipher_text_area.len());

        let sector_size = self.block_size as usize;
        let first_sector_index = cipher_text_block_start_offset / self.block_size;
        // decrypt old cipher text
        // let mut plain_text_area = vec![0u8; related_cipher_text_area.len()];
        // plain_text_area.copy_from_slice(related_cipher_text_area);
        // xts.decrypt_area(
        //     &mut plain_text_area,
        //     sector_size, // `sector size` is equal to `block size`
        //     first_sector_index as u128,
        //     xts_mode::get_tweak_default,
        // );
        let decryption_manager = SGXEncryptionManager::new(DEFAULT_ENCLAVE_PATH, sector_size)
            .expect("create encryption manager failed");
        let plain_text_area = decryption_manager
            .sgx_aes_xts_128bit_key_in_sgx_decryption(related_cipher_text_area, first_sector_index)
            .expect("decrypt failed");
        let pos_offset_in_block = (pos % self.block_size) as usize;
        let bytes_read = std::io::Read::read(&mut &plain_text_area[pos_offset_in_block..], buf)?;
        // buf.write(&plain_text_area[pos as usize..pos as usize + n]);
        self.pos += bytes_read as u64;
        Ok(n)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        let mut nread = 0;
        for buf in bufs {
            let n = self.read(buf)?;
            nread += n;
            if n < buf.len() {
                break;
            }
        }
        Ok(nread)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        // dbg!(n);
        let pos = std::cmp::min(self.pos, self.inner.as_ref().len() as u64);
        if pos + buf.len() as u64 > self.inner.as_ref().len() as u64 {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        let cipher_text_block_start_offset = self.block_size * (pos / self.block_size);
        let cipher_text_block_end_offset =
            (pos + buf.len() as u64).div_ceil(self.block_size) * self.block_size;

        let related_cipher_text_area = &self.inner.as_ref()
            [cipher_text_block_start_offset as usize..cipher_text_block_end_offset as usize];
        // dbg!(cipher_text_area.len());

        let sector_size = self.block_size as usize;
        let first_sector_index = cipher_text_block_start_offset / self.block_size;

        // decrypt old cipher text
        let decryption_manager = SGXEncryptionManager::new(DEFAULT_ENCLAVE_PATH, sector_size)
            .expect("create encryption manager failed");
        let plain_text_area = decryption_manager
            .sgx_aes_xts_128bit_key_in_sgx_decryption(related_cipher_text_area, first_sector_index)
            .expect("decrypt failed");
        // dbg!(bytes_read_offset);

        let start_offset_in_block = (pos % self.block_size) as usize;
        std::io::Read::read_exact(&mut &plain_text_area[start_offset_in_block..], buf)?;
        self.pos += buf.len() as u64;
        Ok(())
        // buf.write(&plain_text_area[pos as usize..pos as usize + n]);
    }
}

/// TODO: encyption happens in here!
impl<T> TDECursor<T>
where
    T: AsMut<[u8]>,
{
    // Non-resizing write implementation
    // TODO: encyption happens in here!

    #[inline]
    fn slice_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let pos = std::cmp::min(self.pos, self.inner.as_mut().len() as u64);
        let write_offset = pos + buf.len() as u64;
        // if write_offset > self.inner.as_mut().len() as u64 {
        //     write_offset = self.inner.as_mut().len() as u64;
        // }
        // determine the block range to be decrypted and re-encrypted
        let old_cipher_text_block_start_offset = self.block_size * (pos / self.block_size);
        let old_cipher_text_block_end_offset =
            (write_offset).div_ceil(self.block_size) * self.block_size;

        // copy the old cipher text blocks to handle it in memory,
        // and write back to the image file later
        let old_cipher_text_area = &self.inner.as_mut()[old_cipher_text_block_start_offset as usize
            ..old_cipher_text_block_end_offset as usize];
        // dbg!(old_cipher_text_area.len());

        // decrypt old cipher text
        let sector_size = self.block_size as usize;
        let first_sector_index = old_cipher_text_block_start_offset / self.block_size;
        let encryption_decryption_manager =
            SGXEncryptionManager::new(DEFAULT_ENCLAVE_PATH, sector_size)
                .expect("create encryption manager failed");
        let mut old_plaintext = encryption_decryption_manager
            .sgx_aes_xts_128bit_key_in_sgx_decryption(old_cipher_text_area, first_sector_index)
            .expect("decrypt failed");

        // replace the outdated part with new plain text
        let mut plaintext_cursor = Cursor::new(&mut old_plaintext);
        plaintext_cursor.seek(SeekFrom::Start(pos - old_cipher_text_block_start_offset))?;
        plaintext_cursor.write_all(buf)?;

        // encrypt the whole blocks again
        let new_plaintext_encrypted = encryption_decryption_manager
            .sgx_aes_xts_128bit_key_in_sgx_encryption(&old_plaintext, first_sector_index)
            .expect("encrypt failed");

        // write back to image file
        let mut write_area = &mut self.inner.as_mut()[old_cipher_text_block_start_offset as usize
            ..old_cipher_text_block_end_offset as usize];
        std::io::Write::write(&mut write_area, &new_plaintext_encrypted)?;

        self.pos += buf.len() as u64;
        std::io::Result::Ok(buf.len())
    }

    #[inline]
    fn slice_write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        let mut nwritten = 0;
        for buf in bufs {
            let n = self.slice_write(buf)?;
            nwritten += n;
            if n < buf.len() {
                break;
            }
        }
        Ok(nwritten)
    }
}

impl<T> std::io::Write for TDECursor<T>
where
    T: AsMut<[u8]>,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.slice_write(buf)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.slice_write_vectored(bufs)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.as_mut().flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::init_test_environment::{init_test_environment, DEFAULT_KEY_MANAGER_PATH};
    use std::io::{Read, Seek, Write};
    /// test if the data has ever been encrypted
    #[test]
    fn test_encryption() {
        init_test_environment("/tmp/b", DEFAULT_KEY_MANAGER_PATH, 101);
        let mut cursor = TDECursor::new([0u8; 1024], 512);
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let buf = vec![0u8; 1024];
        cursor.write_all(&buf).unwrap();
        // data written to cursor should be encrypted
        assert_ne!(cursor.inner, [0; 1024]);
    }
    /// test if the data can transparently be encrypted and decrypted
    #[test]
    fn test_transparent_encryption() {
        init_test_environment("/tmp/a", DEFAULT_KEY_MANAGER_PATH, 150);
        // test case 1, write 512 bytes at offset 512
        // test write [BLOCK_SIZE] contents to [BLOCK SIZE] offset
        let mut cursor = TDECursor::new([0u8; 1024], 512);
        cursor.seek(SeekFrom::Start(512)).unwrap();
        let bytes_written = cursor.write(&[1u8; 512]).unwrap();
        assert_eq!(bytes_written, 512);

        cursor.seek(SeekFrom::Start(512)).unwrap();
        let mut buf = vec![0u8; 512];
        cursor.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [1; 512]);

        // test case 2, write 512 bytes at offset 102
        // test write [BLOCK_SIZE] contents to [NON BLOCK SIZE] offset
        cursor.seek(SeekFrom::Start(102)).unwrap();
        let size = cursor.write(&[2u8; 512]).unwrap();
        assert_eq!(size, 512);

        cursor.seek(SeekFrom::Start(102)).unwrap();
        let mut buf = vec![0u8; 512];
        cursor.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [2; 512]);

        // test case 3, write 36 bytes at offset 755
        // test write [NON BLOCK_SIZE] contents to [NON BLOCK SIZE] offset
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let size = cursor.write(&[1, 3, 8, 7, 6, 29]).unwrap();
        assert_eq!(size, 6);
        // test if the cursor position is correct
        assert_eq!(cursor.position(), 6);
        let size = cursor.write(&[1, 2, 3, 4]).unwrap();
        assert_eq!(size, 4);
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = vec![0; 10];
        cursor.read_exact(&mut buf).unwrap();
        // test if the cursor position is correct
        assert_eq!(cursor.position(), 10);
        assert_eq!(buf, [1, 3, 8, 7, 6, 29, 1, 2, 3, 4]);
    }
}
