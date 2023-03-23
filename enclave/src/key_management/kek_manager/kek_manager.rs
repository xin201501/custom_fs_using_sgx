use sgx_serialize::{opaque, Deserialize, Serialize};
use sgx_tseal::seal::SealedData;
use std::{collections::BTreeMap, path::PathBuf};
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KekManager {
    /// underlying file path
    pub(super) kek_path: PathBuf,
    /// hashmap of all user keys
    pub(super) user_keks: BTreeMap<u32, [u8; 16]>,
}

impl KekManager {
    pub fn user_keks_ref(&self) -> &BTreeMap<u32, [u8; 16]> {
        &self.user_keks
    }

    pub fn user_keks_mut(&mut self) -> &mut BTreeMap<u32, [u8; 16]> {
        &mut self.user_keks
    }
}

/// write keks in [KekManager] to underlying file
impl Drop for KekManager {
    fn drop(&mut self) {
        let encoded_keks = opaque::encode(&self.user_keks).expect("encode error!");
        let sealed_keks =
            SealedData::<[u8]>::seal(encoded_keks.as_slice(), None).expect("seal failed!");

        std::fs::write(&self.kek_path, sealed_keks.into_bytes().unwrap())
            .expect("write kek file failed!");
    }
}
