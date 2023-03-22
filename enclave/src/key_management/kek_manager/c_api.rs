use std::{
    fs::File,
    path::Path,
    sync::RwLock,
};

use argon2::Argon2;
use once_cell::sync::OnceCell;
use sgx_rand::Rng;
use sgx_serialize::opaque;
use sgx_tseal::seal::{SealedData, UnsealedData};
use sgx_types::error::SgxStatus;
use sgx_unit_test::run_unit_tests;

use crate::key_management::wrap_key;
use crate::key_management::KekManager;

static GLOBAL_KEK_MANAGER_FOR_APP: OnceCell<RwLock<KekManager>> = OnceCell::new();
static GLOBAL_KEK_MANAGER_PATH: OnceCell<String> = OnceCell::new();
#[no_mangle]
pub extern "C" fn init_kek_manager(kek_path: *const u8, kek_path_len: usize) {
    let kek_path = unsafe { std::slice::from_raw_parts(kek_path, kek_path_len) };

    let kek_path = String::from_utf8(kek_path.to_owned()).expect("sdsdada");
    // let kek_path = kek_path.to_str().expect("to str failed!");
    GLOBAL_KEK_MANAGER_PATH.get_or_init(|| kek_path.to_string());

    let kek_path = Path::new(&kek_path);
    GLOBAL_KEK_MANAGER_FOR_APP.get_or_init(|| {
        if kek_path.exists() {
            // read keks from file
            let encrypted_bytes = std::fs::read(kek_path).expect("read KEK failed!");
            let unsealed_bytes =
                UnsealedData::<[u8]>::unseal_from_bytes(encrypted_bytes).expect("unseal failed!");
            let keks = opaque::decode(unsealed_bytes.to_plaintext())
                .ok_or(SgxStatus::Unexpected)
                .expect("get existing KEKs failed!");

            RwLock::new(KekManager {
                kek_path: kek_path.to_path_buf(),
                user_keks: keks,
            })
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
fn lookup_user_key(user_id: u32) -> Option<[u8; 16]> {
    let lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first!")
        .read()
        .unwrap();
    lock.user_keks_ref().get(&user_id).copied()
}

/// check if a user's password is correct
/// # Parameters
/// - `user_id`: uid
/// - `claimed_user_password`: claimed password
/// - `claimed_user_password_len`: length of `claimed_user_password`
#[no_mangle]
pub extern "C" fn check_user_password_outside_sgx(
    user_id: u32,
    claimed_user_password: *const u8,
    claimed_user_password_len: usize,
) -> SgxStatus {
    let claimed_user_password =
        unsafe { std::slice::from_raw_parts(claimed_user_password, claimed_user_password_len) };
    let right_kek = lookup_user_key(user_id);
    match right_kek {
        None => SgxStatus::InvalidParameter,
        Some(kek) => {
            let binding = blake3::hash(&user_id.to_be_bytes());
            let salt = binding.as_bytes();
            let argon2 = Argon2::default();
            let mut calculated_kek = [0u8; 16];
            argon2
                .hash_password_into(claimed_user_password, salt, &mut calculated_kek)
                .expect("hash password failed!");
            
            let is_valid = kek == calculated_kek;

            if is_valid {
                SgxStatus::Success
            } else {
                SgxStatus::InvalidParameter
            }
        }
    }
}

fn check_user_password_in_sgx(
    user_id: u32,
    claimed_user_password: &[u8],
) -> (bool, Option<[u8; 16]>) {
    let kek = lookup_user_key(user_id);
    match kek {
        None => (false, None),
        Some(kek) => {
            let binding = blake3::hash(&user_id.to_be_bytes());
            let salt = binding.as_bytes();
            let argon2 = Argon2::default();
            let mut calculated_kek = [0u8; 16];
            argon2
                .hash_password_into(claimed_user_password, salt, &mut calculated_kek)
                .expect("hash password failed!");

            (kek == calculated_kek, Some(calculated_kek))
        }
    }
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
    user_id: u32,
    user_password: *const u8,
    user_password_len: usize,
) -> SgxStatus {
    dbg!(user_id);
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

    let mut user_password = lock.user_keks_mut().get(&user_id);
    // if user_id already exists, return error,
    // else insert user_id and user_kek
    match user_password {
        Some(_) => SgxStatus::InvalidParameter,
        None => {
            lock.user_keks_mut().insert(user_id, user_kek);
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
    user_id: u32,
    old_password: *const u8,
    old_password_len: usize,
    new_password: *const u8,
    new_password_len: usize,
) -> SgxStatus {
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
    let kek_map = lock.user_keks_mut();
    if kek_map.get(&user_id) != Some(&calculated_old_kek) {
        return SgxStatus::InvalidParameter;
    }
    let new_password = unsafe { core::slice::from_raw_parts(new_password, new_password_len) };
    let mut new_kek = [0u8; 16];
    argon2
        .hash_password_into(new_password, salt, &mut new_kek)
        .expect("hash password failed!");
    // update kek
    // `insert` method will replace the old value if the key already exists
    kek_map.insert(user_id, new_kek);
    SgxStatus::Success
}

#[no_mangle]
pub extern "C" fn save_kek_manager() {
    let lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .write()
        .unwrap();
    let keks = lock.user_keks_ref();
    let encoded_keks = opaque::encode(keks).expect("encode error!");
    let sealed_keks =
        SealedData::<[u8]>::seal(encoded_keks.as_slice(), None).expect("seal failed!");

    std::fs::write(
        &GLOBAL_KEK_MANAGER_PATH.get().unwrap(),
        sealed_keks.into_bytes().unwrap(),
    )
    .expect("write kek file failed!");
}

#[no_mangle]
pub extern "C" fn generate_random_wrapped_key(
    user_id: u32,
    password: *const u8,
    password_len: usize,
    wrapped_key: *mut u8,
    wrapped_key_len: usize,
) -> SgxStatus {
    let claimed_user_password = unsafe { core::slice::from_raw_parts(password, password_len) };
    let wrapped_key = unsafe { core::slice::from_raw_parts_mut(wrapped_key, wrapped_key_len) };

    let check_user_kek_result = check_user_password_in_sgx(user_id, claimed_user_password);
    if !check_user_kek_result.0 {
        return SgxStatus::InvalidParameter;
    }

    match check_user_kek_result.1 {
        Some(user_kek) => {
            let mut rng = sgx_rand::thread_rng();
            let mut random_key = [0u8; 16];
            rng.fill_bytes(&mut random_key);

            // TODO: key wrapping
            match wrap_key::wrap_key(&user_kek, &random_key, wrapped_key) {
                Ok(_) => SgxStatus::Success,
                Err(_) => SgxStatus::Unexpected,
            }
        }
        None => SgxStatus::InvalidParameter,
    }
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

    assert_eq!(lock.user_keks_ref().len(), 1);
    assert_eq!(lock.user_keks_ref().get(&user_id), Some(&correct_user_kek));
    drop(lock);
    // if user kek already exists, create will fail
    unsafe {
        assert_eq!(
            create_user_kek(user_id, user_password.as_ptr(), user_password.len()),
            SgxStatus::InvalidParameter
        )
    };
}

fn test_check_user_key_ouside_sgx() {
    let user_id = 4u32;
    let user_password = "old password";
    let mut correct_user_kek = [0u8; 16];
    let binding = blake3::hash(&user_id.to_be_bytes());
    let salt = binding.as_bytes();
    Argon2::default()
        .hash_password_into(user_password.as_bytes(), salt, &mut correct_user_kek)
        .unwrap();
    let mut lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .write()
        .unwrap();
    lock.user_keks_mut().clear();
    drop(lock);

    let result =
        check_user_password_outside_sgx(user_id, user_password.as_ptr(), user_password.len());
    assert_eq!(result, SgxStatus::InvalidParameter);
    let mut lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .write()
        .unwrap();

    lock.user_keks_mut().insert(user_id, correct_user_kek);
    drop(lock);
    let result =
        check_user_password_outside_sgx(user_id, user_password.as_ptr(), user_password.len());
    assert_eq!(result, SgxStatus::Success);

    let wrong_password = "wrong password";
    let result =
        check_user_password_outside_sgx(user_id, wrong_password.as_ptr(), wrong_password.len());
    assert_eq!(result, SgxStatus::InvalidParameter);
}

fn test_lookup_user_kek() {
    let user_id = 2;
    let user_kek = [1u8; 16];
    let mut lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .write()
        .unwrap();
    lock.user_keks_mut().insert(user_id, user_kek);
    drop(lock);
    let fetched_user_kek = unsafe { lookup_user_key(user_id) };
    assert_eq!(Some(user_kek), fetched_user_kek);
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
            SgxStatus::InvalidParameter
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
            SgxStatus::InvalidParameter
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
            SgxStatus::Success
        );
    }
}

fn test_save_user_kek() {
    let mut lock = GLOBAL_KEK_MANAGER_FOR_APP
        .get()
        .expect("init_kek_manager must be called first")
        .write()
        .unwrap();
    let keks = lock.user_keks_mut();
    keks.clear();
    keks.insert(1, [1u8; 16]);
    keks.insert(2, [2u8; 16]);
    keks.insert(3, [3u8; 16]);
    drop(lock);

    save_kek_manager();
    let kek_manager = KekManager::new(&GLOBAL_KEK_MANAGER_PATH.get().unwrap()).unwrap();
    let keks = kek_manager.user_keks_ref();
    assert_eq!(keks.len(), 3);
    assert_eq!(keks.get(&1), Some(&[1u8; 16]));
    assert_eq!(keks.get(&2), Some(&[2u8; 16]));
    assert_eq!(keks.get(&3), Some(&[3u8; 16]));
}

#[no_mangle]
pub unsafe extern "C" fn run_key_management_c_api_tests() {
    let test_file_path_in_c = "/tmp/kek_manager_c_api_test_update";
    let test_file_path = Path::new(test_file_path_in_c);
    if test_file_path.exists() {
        std::fs::remove_file(test_file_path).expect("remove test file failed!");
    };

    init_kek_manager(test_file_path_in_c.as_ptr(), test_file_path_in_c.len());
    let failed_tests_amount = run_unit_tests!(
        test_create_user_kek,
        test_check_user_key_ouside_sgx,
        test_lookup_user_kek,
        test_update_user_kek,
        test_save_user_kek
    );

    if failed_tests_amount > 0 {
        panic!("{} test(s) failed!", failed_tests_amount);
    }
}
