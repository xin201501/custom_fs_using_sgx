use anyhow::anyhow;
use once_cell::sync::OnceCell;
use sgx_rand::Rng;
use sgx_serialize::{opaque, Deserialize, Serialize};
use sgx_tseal::seal::SealedData;
use sgx_tseal::seal::UnsealedData;
use std::fs::File;
use std::{path::Path, path::PathBuf};
pub const DEFAULT_KEY_MANAGER_PATH: &str = "/tmp/key_manager";
static GLOBAL_KEY_MANAGER: once_cell::sync::OnceCell<KeyManager> = OnceCell::new();
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyManager {
    /// underlying file path
    key_path: PathBuf,
    /// data_encryption_key
    data_encryption_key: [u8; 32],
}
impl KeyManager {
    pub fn new(key_path: impl AsRef<Path>) -> anyhow::Result<&'static KeyManager> {
        let key_path = key_path.as_ref();
        let result = GLOBAL_KEY_MANAGER.get_or_try_init(|| {
            if key_path.exists() {
                // read data encryption key from file
                let encrypted_bytes =
                    std::fs::read(key_path).map_err(|_| anyhow!("read kek file failed!"))?;
                let unsealed_bytes = UnsealedData::<[u8]>::unseal_from_bytes(encrypted_bytes)
                    .map_err(|_| anyhow!("unseal key failed!"))?;
                let data_encryption_key = opaque::decode(unsealed_bytes.to_plaintext())
                    .ok_or(anyhow!("decode error!"))?;

                dbg!(data_encryption_key);
                Ok(Self {
                    key_path: key_path.to_path_buf(),
                    data_encryption_key,
                })
            } else {
                // create data encryption key file
                File::create(key_path)?;
                let data_encryption_key = {
                    let mut rng = sgx_rand::thread_rng();
                    let mut random_key = [0u8; 32];
                    rng.fill_bytes(&mut random_key);
                    random_key
                };
                let encoded_key = opaque::encode(&data_encryption_key).expect("encode error!");
                let sealed_key =
                    SealedData::<[u8]>::seal(encoded_key.as_slice(), None).expect("seal failed!");
                std::fs::write(key_path, sealed_key.into_bytes()?)?;
                Ok(Self {
                    key_path: key_path.to_path_buf(),
                    data_encryption_key,
                })
            }
        });
        result
        // if key_path.exists() {
        //     // read data encryption key from file
        //     let encrypted_bytes =
        //         std::fs::read(key_path).map_err(|_| anyhow!("read key file failed!"))?;
        //     let unsealed_bytes = UnsealedData::<[u8]>::unseal_from_bytes(encrypted_bytes)
        //         .map_err(|_| anyhow!("unseal key failed!"))?;
        //     let data_encryption_key =
        //         opaque::decode(unsealed_bytes.to_plaintext()).ok_or(anyhow!("decode error!"))?;

        //     Ok(Self {
        //         key_path: key_path.to_path_buf(),
        //         data_encryption_key,
        //     })
        // } else {
        //     // create data encryption key file
        //     File::create(key_path)?;
        //     Ok(Self {
        //         key_path: key_path.to_path_buf(),
        //         data_encryption_key: {
        //             let mut rng = sgx_rand::thread_rng();
        //             let mut random_key = [0u8; 32];
        //             rng.fill_bytes(&mut random_key);
        //             random_key
        //         },
        //     })
        // }
    }
}
impl KeyManager {
    pub fn data_encryption_key_ref(&self) -> &[u8; 32] {
        &self.data_encryption_key
    }

    pub fn data_encryption_key_mut(&mut self) -> &mut [u8; 32] {
        &mut self.data_encryption_key
    }
    pub fn key_path_ref(&self) -> &PathBuf {
        &self.key_path
    }
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        let encoded_keks = opaque::encode(&self.data_encryption_key).expect("encode error!");
        let sealed_keks =
            SealedData::<[u8]>::seal(encoded_keks.as_slice(), None).expect("seal failed!");

        std::fs::write(&self.key_path, sealed_keks.into_bytes().unwrap())
            .expect("write kek file failed!");
    }
}
pub fn save_key_manager() {
    let lock = GLOBAL_KEY_MANAGER.get().expect("not init key manager!");
    let key = lock.data_encryption_key_ref();
    let encoded_key = opaque::encode(key).expect("encode error!");
    let sealed_key = SealedData::<[u8]>::seal(encoded_key.as_slice(), None).expect("seal failed!");

    std::fs::write(lock.key_path_ref(), sealed_key.into_bytes().unwrap())
        .expect("write kek file failed!");
}
