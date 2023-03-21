use std::{
    ffi::{c_char, CStr, CString},
    fs::File,
    path::Path,
    sync::RwLock,
};

use argon2::Argon2;
use once_cell::sync::OnceCell;
use sgx_serialize::opaque;
use sgx_tseal::seal::UnsealedData;
use sgx_types::error::SgxStatus;
use sgx_unit_test::run_unit_tests;

use super::KekManager;

static GLOBAL_KEK_MANAGER_FOR_APP: OnceCell<RwLock<KekManager>> = OnceCell::new();

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
            RwLock::new(
                opaque::decode(unsealed_bytes.to_plaintext())
                    .ok_or(SgxStatus::Unexpected)
                    .expect("get existing KEK manager failed!"),
            )
        } else {
            // create kek file
            File::create(kek_path).expect("create KEK storage file failed!");
            RwLock::new(KekManager::default())
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
        .read()
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
) -> SgxStatus {
    let user_password = unsafe { core::slice::from_raw_parts(user_password, user_password_len) };
    let mut user_kek = [0u8; 16];

    let binding = blake3::hash(&user_id.to_be_bytes());
    let salt = binding.as_bytes();

    let argon2 = Argon2::default();
    argon2
        .hash_password_into(user_password, salt, &mut user_kek)
        .expect("hash password failed!");
    let mut lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .write()
        .unwrap();

    let mut user_password = lock.keks_mut().get(&user_id);
    // if user_id already exists, return error,
    // else insert user_id and user_kek
    match user_password {
        Some(_) => SgxStatus::InvalidParameter,
        None => {
            lock.keks_mut().insert(user_id, user_kek);
            SgxStatus::Success
        }
    }
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
    let binding = blake3::hash(&user_id.to_be_bytes());
    let salt = binding.as_bytes();
    argon2
        .hash_password_into(old_password, salt, &mut calculated_old_kek)
        .expect("hash password failed!");

    let mut lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .write()
        .unwrap();
    let kek_map = lock.keks_mut();
    if kek_map.get(&user_id) != Some(&calculated_old_kek) {
        return false;
    }
    let new_password = unsafe { core::slice::from_raw_parts(new_password, new_password_len) };
    let mut new_kek = [0u8; 16];
    argon2
        .hash_password_into(new_password, salt, &mut new_kek)
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

// test create user kek
fn test_create_user_kek() {
    // create `Cstr` from `&str`
    // let test_file_path_in_c =
    //     CString::new("/tmp/kek_manager_c_api_test_create").expect("create test file path failed!");
    // let test_file_path = Path::new(test_file_path_in_c.to_str().unwrap());
    // if test_file_path.exists() {
    //     std::fs::remove_file(test_file_path).expect("remove test file failed!");
    // }
    // GLOBAL_KEK_MANAGER_FOR_APP
    //     .set(RwLock::new(KekManager::new(test_file_path).unwrap()))
    //     .unwrap();

    let user_id = 1;
    let user_password = "old password";
    // if user kek doesn't exist, create will success
    unsafe {
        assert_eq!(
            create_user_kek(user_id, user_password.as_ptr(), user_password.len()),
            SgxStatus::Success
        )
    };

    let mut correct_user_kek = [0u8; 16];
    let binding = blake3::hash(&user_id.to_be_bytes());
    let salt = binding.as_bytes();
    Argon2::default()
        .hash_password_into(user_password.as_bytes(), salt, &mut correct_user_kek)
        .unwrap();
    let lock = GLOBAL_KEK_MANAGER_FOR_APP.get().unwrap().read().unwrap();

    assert_eq!(lock.keks_ref().len(), 1);
    assert_eq!(lock.keks_ref().get(&user_id), Some(&correct_user_kek));
    drop(lock);
    // if user kek already exists, create will fail
    unsafe {
        assert_eq!(
            create_user_kek(user_id, user_password.as_ptr(), user_password.len()),
            SgxStatus::InvalidParameter
        )
    };
}

fn test_lookup_user_kek() {
    let user_id = 2;
    let user_kek = [1u8; 16];
    let mut lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .write()
        .unwrap();
    lock.keks_mut().insert(user_id, user_kek);
    drop(lock);
    let mut fetched_user_kek = [0u8; 16];
    unsafe {
        lookup_user_kek(user_id, &mut fetched_user_kek);
    }
    assert_eq!(user_kek, fetched_user_kek);
}

fn test_update_user_kek() {
    let user_id = 3;
    let user_password = "1234";
    // if user kek does not exist, update will fail
    unsafe {
        assert_eq!(
            update_user_kek(
                user_id,
                user_password.as_ptr(),
                user_password.len(),
                user_password.as_ptr(),
                user_password.len()
            ),
            false
        );
    }
    // create user kek
    unsafe {
        create_user_kek(user_id, user_password.as_ptr(), user_password.len());
    }
    // if user inputs a wrong password, update will fail
    unsafe {
        assert_eq!(
            update_user_kek(
                user_id,
                "wrong_password".as_ptr(),
                "wrong_password".len(),
                user_password.as_ptr(),
                user_password.len()
            ),
            false
        );
    }
    // if user inputs the correct password, update will succeed
    unsafe {
        assert_eq!(
            update_user_kek(
                user_id,
                user_password.as_ptr(),
                user_password.len(),
                "new_password".as_ptr(),
                "new_password".len()
            ),
            true
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn run_key_management_c_api_tests() {
    let test_file_path_in_c =
        CString::new("/tmp/kek_manager_c_api_test_update").expect("create test file path failed!");
    let test_file_path = Path::new(test_file_path_in_c.to_str().unwrap());
    if test_file_path.exists() {
        std::fs::remove_file(test_file_path).expect("remove test file failed!");
    };

    init_kek_manager(test_file_path_in_c.as_ptr());
    run_unit_tests!(
        test_create_user_kek,
        test_lookup_user_kek,
        test_update_user_kek
    );
}
