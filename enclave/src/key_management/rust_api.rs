use super::KekManager;
use anyhow::anyhow;
use argon2::Argon2;
use sgx_serialize::opaque;
use sgx_tseal::seal::UnsealedData;
use sgx_unit_test::run_unit_tests;
use std::{fs::File, path::Path};

impl KekManager {
    pub fn new(kek_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let kek_path = kek_path.as_ref();
        if kek_path.exists() {
            // read keks from file
            let encrypted_bytes =
                std::fs::read(kek_path).map_err(|_| anyhow!("read kek file failed!"))?;
            let unsealed_bytes = UnsealedData::<[u8]>::unseal_from_bytes(encrypted_bytes)
                .map_err(|_| anyhow!("unseal kek failed!"))?;
            let keks =
                opaque::decode(unsealed_bytes.to_plaintext()).ok_or(anyhow!("decode error!"))?;
            Ok(Self {
                kek_path: kek_path.to_path_buf(),
                keks,
            })
        } else {
            // create kek file
            File::create(kek_path)?;
            Ok(Self {
                kek_path: kek_path.to_path_buf(),
                keks: Default::default(),
            })
        }
    }
}

impl KekManager {
    pub fn lookup(&self, user_id: u16) -> Option<[u8; 16]> {
        self.keks.get(&user_id).copied()
    }

    pub fn update(
        &mut self,
        user_id: u16,
        old_password: &[u8],
        new_password: &[u8],
    ) -> anyhow::Result<()> {
        let binding = blake3::hash(&user_id.to_be_bytes());
        let salt = binding.as_bytes();

        let mut calculated_user_kek = [0u8; 16];
        let argon2 = Argon2::default();
        argon2
            .hash_password_into(old_password, salt, &mut calculated_user_kek)
            .map_err(|_| anyhow!("hash password failed!"))?;
        if self.keks.get(&user_id) != Some(&calculated_user_kek) {
            return Err(anyhow!("user id or old password is wrong!"));
        }

        argon2
            .hash_password_into(new_password, salt, &mut calculated_user_kek)
            .map_err(|_| anyhow!("hash password failed!"))?;
        // update kek
        // `insert` method will replace the old value if the key already exists
        self.keks.insert(user_id, calculated_user_kek);
        Ok(())
    }
}

fn test_kek_manager_init() {
    let kek_manager_init_file = Path::new("/tmp/kek_manager_init");
    if kek_manager_init_file.exists() {
        std::fs::remove_file(kek_manager_init_file).unwrap();
    }
    let kek_manager = KekManager::new("/tmp/kek_manager_init").unwrap();
    assert_eq!(kek_manager.keks_ref().len(), 0);
}

fn test_kek_manager_drop() -> anyhow::Result<()> {
    let kek_manager_drop_file = Path::new("/tmp/kek_manager_drop");
    if kek_manager_drop_file.exists() {
        std::fs::remove_file(kek_manager_drop_file)?;
    }
    let mut kek_manager = KekManager::new(kek_manager_drop_file)?;
    // randonly insert some keks
    kek_manager.keks_mut().insert(1, [1u8; 16]);
    kek_manager.keks_mut().insert(2, [2u8; 16]);
    kek_manager.keks_mut().insert(3, [3u8; 16]);
    // drop kek_manager
    drop(kek_manager);
    // read keks from file
    let kek_manager = KekManager::new(kek_manager_drop_file)?;
    assert_eq!(kek_manager.keks_ref().len(), 3);
    let keks = kek_manager.keks_ref();
    assert_eq!(keks.get(&1), Some(&[1u8; 16]));
    assert_eq!(keks.get(&2), Some(&[2u8; 16]));
    assert_eq!(keks.get(&3), Some(&[3u8; 16]));
    Ok(())
}

fn test_kek_manager_lookup() {
    let kek_manager_lookup_file = Path::new("/tmp/kek_manager_lookup");
    if kek_manager_lookup_file.exists() {
        std::fs::remove_file(kek_manager_lookup_file).unwrap();
    }

    let mut kek_manager = KekManager::new("/tmp/kek_manager_lookup").unwrap();

    // if `user id` doesn't exist, lookup will return None
    assert_eq!(kek_manager.lookup(1), None);
    let user_id = 1;
    let kek = [1u8; 16];
    kek_manager.keks_mut().insert(user_id, kek);
    // if `user id` exists, lookup will return the corresponding kek
    assert_eq!(kek_manager.lookup(1), Some([1u8; 16]));
}

fn test_kek_manager_update() {
    let kek_manager_update_file = Path::new("/tmp/kek_manager_update");
    if kek_manager_update_file.exists() {
        std::fs::remove_file(kek_manager_update_file).expect("remove file failed!");
    }

    let mut kek_manager = KekManager::new(kek_manager_update_file).unwrap();
    let user_id = 1;

    let old_password = b"old_password";
    let new_password = b"new_password";

    // if the user id is not found, update will fail
    assert!(kek_manager
        .update(user_id, old_password, new_password)
        .is_err());

    kek_manager.keks_mut().insert(user_id, [1u8; 16]);

    // if the old password is wrong, update will fail
    assert!(kek_manager
        .update(user_id, old_password, new_password)
        .is_err());

    let binding = blake3::hash(&user_id.to_be_bytes());
    let salt = binding.as_bytes();

    // correct old password
    let mut old_user_kek = [0u8; 16];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(old_password, salt, &mut old_user_kek)
        .expect("hash password failed!");
    kek_manager.keks_mut().insert(user_id, old_user_kek);

    // if the old password is correct, update will succeed
    kek_manager
        .update(user_id, old_password, new_password)
        .unwrap();

    let mut calculated_new_user_kek = [0u8; 16];
    argon2
        .hash_password_into(new_password, salt, &mut calculated_new_user_kek)
        .expect("hash password failed!");

    // check if the updated new kek is correct
    assert_eq!(kek_manager.lookup(1), Some(calculated_new_user_kek));
}

#[no_mangle]
pub unsafe extern "C" fn run_key_management_rust_api_tests() {
    let failed_tests_amount = run_unit_tests!(
        test_kek_manager_init,
        test_kek_manager_drop,
        test_kek_manager_lookup,
        test_kek_manager_update
    );
    if failed_tests_amount > 0 {
        panic!("{} test(s) failed!", failed_tests_amount);
    }
}
