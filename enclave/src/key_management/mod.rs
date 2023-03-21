use sgx_serialize::{opaque, Deserialize, Serialize};
use sgx_tseal::seal::SealedData;
use std::{collections::BTreeMap, path::PathBuf};
mod c_api;
mod rust_api;
mod wrap_key;
mod test_third_party_crates;
pub use c_api::*;
pub use rust_api::*;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KekManager {
    /// underlying file path
    kek_path: PathBuf,
    /// hashmap of all keks
    keks: BTreeMap<u16, [u8; 16]>,
}

impl KekManager {
    pub fn keks_ref(&self) -> &BTreeMap<u16, [u8; 16]> {
        &self.keks
    }

    pub fn keks_mut(&mut self) -> &mut BTreeMap<u16, [u8; 16]> {
        &mut self.keks
    }
}

/// write keks in [KekManager] to underlying file
impl Drop for KekManager {
    fn drop(&mut self) {
        let encoded_keks = opaque::encode(&self.keks).expect("encode error!");
        let sealed_keks =
            SealedData::<[u8]>::seal(encoded_keks.as_slice(), None).expect("seal failed!");

        std::fs::write(&self.kek_path, sealed_keks.into_bytes().unwrap())
            .expect("write kek file failed!");
    }
}
