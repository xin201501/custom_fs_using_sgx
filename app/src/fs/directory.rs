use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use crate::utils;

use utils::traits::{DigestInSelf, SerializeAndDigest};
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Directory {
    pub entries: BTreeMap<OsString, u64>,
    pub digest: [u8; 32],
}

impl Directory {
    pub fn entry<P>(&self, path: P) -> Option<u64>
    where
        P: AsRef<Path>,
    {
        self.entries
            .get(&path.as_ref().as_os_str().to_os_string())
            .copied()
    }

    pub fn get_entries(&self) -> &BTreeMap<OsString, u64> {
        &self.entries
    }
    pub fn get_entries_mut(&mut self) -> &mut BTreeMap<OsString, u64> {
        &mut self.entries
    }
}

impl DigestInSelf for Directory {
    fn digest(&mut self) {
        self.digest = [0u8; 32];
        self.digest = utils::digest::digest(self).expect("digest failed");
    }

    fn verify_digest(&mut self) -> bool {
        let digest_to_verify = self.digest;
        self.digest = [0u8; 32];
        let ok = digest_to_verify == utils::digest::digest(&self).expect("digest failed");
        self.digest = digest_to_verify;
        ok
    }
}
impl SerializeAndDigest for Directory {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn test_directory_serialization_and_deserialization() -> anyhow::Result<()> {
        let mut entries = BTreeMap::new();
        entries.insert(OsString::from("test1.txt"), 1);
        entries.insert(OsString::from("test2.txt"), 2);
        let mut dir = Directory {
            entries,
            digest: [0u8; 32],
        };
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        dir.serialize_into(&mut cursor)?;
        cursor.set_position(0);
        let deserialized = Directory::deserialize_from(&mut cursor)?;
        assert_eq!(deserialized.entries.len(), 2);

        // for (i, (path, inode)) in deserialized.entries.iter().enumerate() {
        //     if i == 0 {
        //         assert_eq!(path, &OsString::from("bar.txt"));
        //         assert_eq!(*inode, 2);
        //     } else {
        //         assert_eq!(path, &OsString::from("foo.txt"));
        //         assert_eq!(*inode, 1);
        //     }
        // }
        let mut iter = deserialized.entries.iter();
        assert_eq!(iter.next(), Some((&OsString::from("test1.txt"), &1)));
        assert_eq!(iter.next(), Some((&OsString::from("test2.txt"), &2)));

        Ok(())
    }

    #[test]
    fn test_directory_entry() {
        let mut entries = BTreeMap::new();
        entries.insert(OsString::from("test1.txt"), 1);
        entries.insert(OsString::from("test2.txt"), 2);
        let dir = Directory {
            entries,
            digest: [0u8; 32],
        };

        assert_eq!(dir.entry("test1.txt"), Some(1));
        assert_eq!(dir.entry("test2.txt"), Some(2));
        assert_eq!(dir.entry("test3.txt"), None);
    }
}
