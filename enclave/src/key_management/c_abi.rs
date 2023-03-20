use std::{
    ffi::{c_char, CStr},
    fs::OpenOptions,
    path::Path,
    sync::Mutex,
};

use argon2::Argon2;
use once_cell::sync::OnceCell;
use sgx_serialize::opaque;
use sgx_tseal::seal::UnsealedData;
use sgx_types::error::SgxStatus;

use super::KekManager;

static GLOBAL_KEK_MANAGER_FOR_APP: OnceCell<Mutex<KekManager>> = OnceCell::new();

#[no_mangle]
pub extern "C" fn init_kek_manager(kek_path: *const c_char) {
    let kek_path = unsafe { CStr::from_ptr(kek_path) };
    let kek_path = kek_path.to_str().expect("to str failed!");
    let kek_path = Path::new(kek_path);
    GLOBAL_KEK_MANAGER_FOR_APP.get_or_init(|| {
        if kek_path.exists() {
            // read keks from file
            let encrypted_bytes = std::fs::read(kek_path).expect("read KEK failed!");
            let unsealed_bytes =
                UnsealedData::<[u8]>::unseal_from_bytes(encrypted_bytes).expect("unseal failed!");
            Mutex::new(
                opaque::decode(unsealed_bytes.to_plaintext())
                    .ok_or(SgxStatus::Unexpected)
                    .expect("get existing KEK manager failed!"),
            )
        } else {
            // create kek file
            OpenOptions::new()
                .create(true)
                .open(kek_path)
                .expect("create KEK storage file failed!");
            Default::default()
        }
    });
}
/// lookup a kek
/// # Safety
/// **must call [init_kek_manager] first** to use this function
#[no_mangle]
pub unsafe extern "C" fn lookup_user_kek(user_id: u16, kek: &mut [u8; 16]) {
    let lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first!")
        .lock()
        .unwrap();
    let result = lock
        .keks_ref()
        .get(&user_id)
        .expect("{user_id}'s kek doesn't exist");
    kek.copy_from_slice(result);
}
/// create user kek using `user_id` and `user_password`
/// # Parameters
/// - `user_id`: uid
/// - `user_password`: password
/// - `user_password_len`: length of `user_password`
/// - `user_kek`: result
/// # Safety
/// **must call [init_kek_manager] first** to use this function\
/// `user_password` **must be a valid pointer to a byte array of length `user_password_len`**.
#[no_mangle]
pub unsafe extern "C" fn create_user_kek(
    user_id: u16,
    user_password: *const u8,
    user_password_len: usize,
) {
    let user_password = unsafe { core::slice::from_raw_parts(user_password, user_password_len) };
    let mut user_kek = [0u8; 16];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(user_password, &user_id.to_be_bytes(), &mut user_kek)
        .expect("hash password failed!");
    GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .lock()
        .unwrap()
        .keks_mut()
        .insert(user_id, user_kek);
}

/// update a user's KEK
/// # Parameters
/// - `user_id`: uid
/// - `old_password`: old password
/// - `old_password_len`: length of `old_password`
/// - `new_password`: new password
/// - `new_password_len`: length of `new_password`
/// # Safety
/// **must call [init_kek_manager] first** to use this function\
/// `old_password` and `new_password` **must be a valid pointer to a byte array of length `old_password_len` and `new_password_len` respectively**.
#[no_mangle]
pub unsafe extern "C" fn update_user_kek(
    user_id: u16,
    old_password: *const u8,
    old_password_len: usize,
    new_password: *const u8,
    new_password_len: usize,
) -> bool {
    let old_password = unsafe { core::slice::from_raw_parts(old_password, old_password_len) };
    let mut calculated_old_kek = [0u8; 16];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(
            old_password,
            &user_id.to_be_bytes(),
            &mut calculated_old_kek,
        )
        .expect("hash password failed!");

    let mut kek_map = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .lock()
        .unwrap();
    let kek_map = kek_map.keks_mut();
    if kek_map.get(&user_id) != Some(&calculated_old_kek) {
        return false;
    }
    let new_password = unsafe { core::slice::from_raw_parts(new_password, new_password_len) };
    let mut new_kek = [0u8; 16];
    argon2
        .hash_password_into(new_password, &user_id.to_be_bytes(), &mut new_kek)
        .expect("hash password failed!");
    // update kek
    // `insert` method will replace the old value if the key already exists
    kek_map.insert(user_id, new_kek);
    true
}

/// ref: https://docs.rs/argon2/0.5.0/argon2
#[no_mangle]
pub extern "C" fn test_argon2_kdf() {
    let password = b"hunter42"; // Bad password; don't actually use!
    let salt = b"example salt"; // Salt should be unique per password
    let mut output_key_material = [0u8; 32]; // Can be any desired size
    Argon2::default()
        .hash_password_into(password, salt, &mut output_key_material)
        .unwrap();
}
