use std::io::{Read, Write};

use anyhow::{anyhow, Ok};
use serde::{de::DeserializeOwned, Serialize};

/// Trait for digesting an object which stores digest in the object itself
pub trait DigestInSelf {
    fn digest(&mut self);
    fn verify_digest(&mut self) -> bool;
}

/// Trait for serializing and deserializing an object which stores digest in the object itself
/// # Note
/// This trait is implemented for all types implementing
/// [Serialize] and [DeserializeOwned] and [DigestInSelf]
pub trait SerializeAndDigest: Serialize + DeserializeOwned + DigestInSelf {
    /// serialize into a writer implementing [Write](std::io::Write)
    /// # Returns
    /// The number of bytes written if successful
    fn serialize_into<W>(&mut self, w: &mut W) -> anyhow::Result<usize>
    where
        W: Write,
    {
        self.digest();
        let config = bincode::config::legacy();
        bincode::serde::encode_into_std_write(self, w, config).map_err(|e| e.into())
    }

    /// serialize into a [Vec](std::vec::Vec)
    fn serialize(&mut self) -> anyhow::Result<Vec<u8>> {
        self.digest();
        let config = bincode::config::legacy();
        bincode::serde::encode_to_vec(self, config).map_err(|e| e.into())
    }

    /// deserialize from a reader implementing [Read](std::io::Read)
    /// # Returns
    /// The deserialized object if successful
    fn deserialize_from<R>(r: &mut R) -> anyhow::Result<Self>
    where
        R: Read,
    {
        let config = bincode::config::legacy();
        let mut object: Self = bincode::serde::decode_from_std_read(r, config)?;
        if !object.verify_digest() {
            Err(anyhow!(concat!(
                "deserialized object digest verification failed"
            )))
        } else {
            Ok(object)
        }
    }
    /// deserialize from a slice
    /// # Returns
    /// A tuple containing the deserialized object and the number of bytes read
    fn deserialize(buf: &[u8]) -> anyhow::Result<(Self, usize)> {
        let config = bincode::config::legacy();
        let (mut object, bytes_read): (Self, usize) =
            bincode::serde::decode_from_slice(buf, config)?;
        if !object.verify_digest() {
            Err(anyhow!(concat!(
                "deserialized object digest verification failed"
            )))
        } else {
            Ok((object, bytes_read))
        }
    }
}
