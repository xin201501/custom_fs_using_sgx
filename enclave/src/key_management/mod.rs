use sgx_serialize::{Deserialize, Serialize};
use std::collections::HashMap;
mod c_abi;
mod rust_abi;
pub use c_abi::*;
pub use rust_abi::*;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KekManager {
    /// hashmap of all keks
    keks: HashMap<u16, [u8; 16]>,
}

impl KekManager {
    pub fn keks_ref(&self) -> &HashMap<u16, [u8; 16]> {
        &self.keks
    }
    pub fn keks_mut(&mut self) -> &mut HashMap<u16, [u8; 16]> {
        &mut self.keks
    }
}
