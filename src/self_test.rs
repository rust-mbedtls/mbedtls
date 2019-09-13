/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

//! Helper functions to enable mbedTLS self tests in no_std.
//!
//! Calling mbedTLS self-test functions before they're enabled using the
//! `enable()` function here will result in a panic.
#[cfg(any(target_os = "none", target_env = "sgx", not(feature = "std")))]
use mbedtls_sys::types::raw::{c_char, c_int};

#[cfg(any(target_os = "none", target_env = "sgx", not(feature = "std")))]
#[allow(non_upper_case_globals)]
static mut rand_f: Option<fn() -> c_int> = None;
#[cfg(any(target_os = "none", target_env = "sgx", not(feature = "std")))]
#[allow(non_upper_case_globals)]
static mut log_f: Option<unsafe fn(*const c_char)> = None;

// needs to be pub for global visiblity
#[cfg(any(target_os = "none", target_env = "sgx", not(feature = "std")))]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn rand() -> c_int {
    rand_f.expect("Called self-test rand without enabling self-test")()
}

// needs to be pub for global visiblity
#[cfg(all(feature = "std", not(target_os = "none")))]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_log(msg: *const std::os::raw::c_char) {
    print!("{}", std::ffi::CStr::from_ptr(msg).to_string_lossy());
}

// needs to be pub for global visiblity
#[cfg(any(target_os = "none", not(feature = "std")))]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_log(msg: *const c_char) {
    log_f.expect("Called self-test log without enabling self-test")(msg)
}

// unsafe since unsynchronized
#[cfg(any(target_os = "none", target_env = "sgx", not(feature = "std")))]
pub unsafe fn enable(rand: fn() -> c_int, log: unsafe fn(*const c_char)) {
    rand_f = Some(rand);
    log_f = Some(log);
}

// unsafe since unsynchronized
#[cfg(any(target_os = "none", target_env = "sgx", not(feature = "std")))]
pub unsafe fn disable() {
    rand_f = None;
    log_f = None;
}

pub use mbedtls_sys::{
    mbedtls_aes_self_test as aes, mbedtls_arc4_self_test as arc4, mbedtls_base64_self_test as base64,
    mbedtls_camellia_self_test as camellia, mbedtls_ccm_self_test as ccm, mbedtls_ctr_drbg_self_test as ctr_drbg,
    mbedtls_des_self_test as des, mbedtls_dhm_self_test as dhm, mbedtls_ecjpake_self_test as ecjpake, mbedtls_ecp_self_test as ecp,
    mbedtls_entropy_self_test as entropy, mbedtls_gcm_self_test as gcm, mbedtls_hmac_drbg_self_test as hmac_drbg,
    mbedtls_md2_self_test as md2, mbedtls_md4_self_test as md4, mbedtls_md5_self_test as md5, mbedtls_mpi_self_test as mpi,
    mbedtls_pkcs5_self_test as pkcs5, mbedtls_ripemd160_self_test as ripemd160, mbedtls_rsa_self_test as rsa,
    mbedtls_sha1_self_test as sha1, mbedtls_sha256_self_test as sha256, mbedtls_sha512_self_test as sha512,
    mbedtls_x509_self_test as x509, mbedtls_xtea_self_test as xtea, mbedtls_nist_kw_self_test as nist_kw
};
