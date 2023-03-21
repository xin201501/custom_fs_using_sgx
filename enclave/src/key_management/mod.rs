use sgx_serialize::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
mod c_api;
mod rust_api;
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
