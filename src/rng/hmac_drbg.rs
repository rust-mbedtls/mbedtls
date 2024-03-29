/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
pub use mbedtls_sys::MBEDTLS_HMAC_DRBG_RESEED_INTERVAL as RESEED_INTERVAL;
use mbedtls_sys::{
    mbedtls_hmac_drbg_random, mbedtls_hmac_drbg_reseed, mbedtls_hmac_drbg_seed,
    mbedtls_hmac_drbg_seed_buf, mbedtls_hmac_drbg_set_prediction_resistance,
    mbedtls_hmac_drbg_update, MBEDTLS_HMAC_DRBG_PR_OFF, MBEDTLS_HMAC_DRBG_PR_ON,
};

use super::{EntropyCallback, RngCallback};
use crate::error::{IntoResult, Result};
use crate::hash::MdInfo;

define!(
    #[c_ty(mbedtls_hmac_drbg_context)]
    struct HmacDrbg<'entropy>;
    const init: fn() -> Self = mbedtls_hmac_drbg_init;
    const drop: fn(&mut Self) = mbedtls_hmac_drbg_free;
);

#[cfg(feature = "threading")]
unsafe impl<'entropy> Sync for HmacDrbg<'entropy> {}

impl<'entropy> HmacDrbg<'entropy> {
    pub fn new<F: EntropyCallback>(
        md_info: MdInfo,
        source: &'entropy mut F,
        additional_entropy: Option<&[u8]>,
    ) -> Result<HmacDrbg<'entropy>> {
        let mut ret = Self::init();
        unsafe {
            mbedtls_hmac_drbg_seed(
                &mut ret.inner,
                md_info.into(),
                Some(F::call),
                source.data_ptr(),
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(ret)
    }

    pub fn from_buf(md_info: MdInfo, entropy: &[u8]) -> Result<HmacDrbg<'entropy>> {
        let mut ret = Self::init();
        unsafe {
            mbedtls_hmac_drbg_seed_buf(
                &mut ret.inner,
                md_info.into(),
                entropy.as_ptr(),
                entropy.len()
            )
            .into_result()?
        };
        Ok(ret)
    }

    pub fn prediction_resistance(&self) -> bool {
        if self.inner.prediction_resistance == MBEDTLS_HMAC_DRBG_PR_OFF {
            false
        } else {
            true
        }
    }

    pub fn set_prediction_resistance(&mut self, pr: bool) {
        unsafe {
            mbedtls_hmac_drbg_set_prediction_resistance(
                &mut self.inner,
                if pr {
                    MBEDTLS_HMAC_DRBG_PR_ON
                } else {
                    MBEDTLS_HMAC_DRBG_PR_OFF
                },
            )
        }
    }

    getter!(entropy_len() -> size_t = .entropy_len);
    setter!(set_entropy_len(len: size_t) = mbedtls_hmac_drbg_set_entropy_len);
    getter!(reseed_interval() -> c_int = .reseed_interval);
    setter!(set_reseed_interval(i: c_int) = mbedtls_hmac_drbg_set_reseed_interval);

    pub fn reseed(&mut self, additional_entropy: Option<&[u8]>) -> Result<()> {
        unsafe {
            mbedtls_hmac_drbg_reseed(
                &mut self.inner,
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(())
    }

    pub fn update(&mut self, entropy: &[u8]) {
        unsafe { mbedtls_hmac_drbg_update(&mut self.inner, entropy.as_ptr(), entropy.len()) };
    }

    // TODO:
    //
    // mbedtls_hmac_drbg_random_with_add
    // mbedtls_hmac_drbg_write_seed_file
    // mbedtls_hmac_drbg_update_seed_file
    //
}

impl<'entropy> RngCallback for HmacDrbg<'entropy> {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        mbedtls_hmac_drbg_random(user_data, data, len)
    }

    fn data_ptr(&mut self) -> *mut c_void {
        &mut self.inner as *mut _ as *mut _
    }
}
