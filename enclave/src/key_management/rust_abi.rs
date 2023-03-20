use super::KekManager;
use anyhow::anyhow;
use argon2::Argon2;
use sgx_serialize::opaque;
use sgx_tseal::seal::UnsealedData;
use sgx_unit_test::run_unit_tests;
use std::{fs::OpenOptions, path::Path};

impl KekManager {
    pub fn new(kek_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let kek_path = kek_path.as_ref();
        if kek_path.exists() {
            // read keks from file
            let encrypted_bytes =
                std::fs::read(kek_path).map_err(|_| anyhow!("read kek file failed!"))?;
            let unsealed_bytes = UnsealedData::<[u8]>::unseal_from_bytes(encrypted_bytes)
                .map_err(|_| anyhow!("unseal failed!"))?;
            opaque::decode(unsealed_bytes.to_plaintext()).ok_or(anyhow!("decode error!"))
        } else {
            // create kek file
            OpenOptions::new().create(true).open(kek_path)?;
            Ok(Self::default())
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
        let mut calculated_user_kek = [0u8; 16];
        let argon2 = Argon2::default();
        argon2
            .hash_password_into(
                old_password,
                &user_id.to_be_bytes(),
                &mut calculated_user_kek,
            )
            .map_err(|_| anyhow!("hash password failed!"))?;
        if self.keks.get(&user_id) != Some(&calculated_user_kek) {
            return Err(anyhow!("user id or old password is wrong!"));
        }
        argon2
            .hash_password_into(
                new_password,
                &user_id.to_be_bytes(),
                &mut calculated_user_kek,
            )
            .map_err(|_| anyhow!("hash password failed!"))?;
        // update kek
        // `insert` method will replace the old value if the key already exists
        self.keks.insert(user_id, calculated_user_kek);
        Ok(())
    }
}

fn test_kek_manager_init() -> anyhow::Result<()> {
    let kek_manager = KekManager::new("/tmp/kek_manager_init")?;
    assert_eq!(kek_manager.keks_ref().len(), 0);
    Ok(())
}

fn test_kek_manager_lookup() -> anyhow::Result<()> {
    let mut kek_manager = KekManager::new("/tmp/kek_manager_lookup")?;
    assert_eq!(kek_manager.lookup(1), None);
    let user_id = 1;
    let kek = [1u8; 16];
    kek_manager.keks_mut().insert(user_id, kek);
    assert_eq!(kek_manager.lookup(1), Some([1u8; 16]));
    Ok(())
}

fn test_kek_manager_update() -> anyhow::Result<()> {
    let mut kek_manager = KekManager::new("/tmp/kek_manager_update")?;
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

    // correct old password
    let mut old_user_kek = [0u8; 16];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(old_password, &user_id.to_be_bytes(), &mut old_user_kek)
        .map_err(|_| anyhow!("hash password failed!"))?;
    kek_manager.keks_mut().insert(user_id, old_user_kek);

    // update kek
    kek_manager.update(user_id, old_password, new_password)?;
    let mut calculated_new_user_kek = [0u8; 16];
    argon2
        .hash_password_into(
            new_password,
            &user_id.to_be_bytes(),
            &mut calculated_new_user_kek,
        )
        .map_err(|_| anyhow!("hash password failed!"))?;

    // check if the new kek is correct
    assert_eq!(kek_manager.lookup(1), Some(calculated_new_user_kek));
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn run_key_management_rust_abi_tests() {
    run_unit_tests!(
        test_kek_manager_init,
        test_kek_manager_lookup,
        test_kek_manager_update
    );
}
