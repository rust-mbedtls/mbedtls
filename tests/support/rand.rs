/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate core;
extern crate mbedtls_sys;
extern crate rand;

use mbedtls_sys::types::raw::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

use rand_xorshift::XorShiftRng;
use rand::{RngCore, SeedableRng};

/// Not cryptographically secure!!! Use for testing only!!!
pub struct TestRandom(XorShiftRng);

impl crate::mbedtls::rng::RngCallback for TestRandom {
    unsafe extern "C" fn call(p_rng: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        (*(p_rng as *mut TestRandom))
            .0
            .fill_bytes(self::core::slice::from_raw_parts_mut(data, len));
        0
    }

    fn data_ptr(&mut self) -> *mut c_void {
        self as *mut _ as *mut _
    }
}

/// Not cryptographically secure!!! Use for testing only!!!
pub fn test_rng() -> TestRandom {
    TestRandom(XorShiftRng::from_seed([1u8; 16]))
}
