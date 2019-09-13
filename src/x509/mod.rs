/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

pub mod certificate;
mod crl;
pub mod csr;
pub mod profile;
// TODO
// write_crt
// write_csr

#[doc(inline)]
pub use self::certificate::{Certificate, LinkedCertificate};
pub use self::crl::Crl;
#[doc(inline)]
pub use self::csr::Csr;
#[doc(inline)]
pub use self::profile::Profile;

use mbedtls_sys::*;
use mbedtls_sys::types::raw::c_uint;

bitflags! {
    #[doc(inline)]
    pub struct KeyUsage: c_uint {
        const DIGITAL_SIGNATURE  = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
        const NON_REPUDIATION    = MBEDTLS_X509_KU_NON_REPUDIATION;
        const KEY_ENCIPHERMENT   = MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
        const DATA_ENCIPHERMENT  = MBEDTLS_X509_KU_DATA_ENCIPHERMENT;
        const KEY_AGREEMENT      = MBEDTLS_X509_KU_KEY_AGREEMENT;
        const KEY_CERT_SIGN      = MBEDTLS_X509_KU_KEY_CERT_SIGN;
        const CRL_SIGN           = MBEDTLS_X509_KU_CRL_SIGN;
        const ENCIPHER_ONLY      = MBEDTLS_X509_KU_ENCIPHER_ONLY;
        const DECIPHER_ONLY      = MBEDTLS_X509_KU_DECIPHER_ONLY;
    }
}

bitflags! {
    #[doc(inline)]
    pub struct VerifyError: u32 {
        const CERT_BAD_KEY       = MBEDTLS_X509_BADCERT_BAD_KEY;
        const CERT_BAD_MD        = MBEDTLS_X509_BADCERT_BAD_MD;
        const CERT_BAD_PK        = MBEDTLS_X509_BADCERT_BAD_PK;
        const CERT_CN_MISMATCH   = MBEDTLS_X509_BADCERT_CN_MISMATCH;
        const CERT_EXPIRED       = MBEDTLS_X509_BADCERT_EXPIRED;
        const CERT_EXT_KEY_USAGE = MBEDTLS_X509_BADCERT_EXT_KEY_USAGE;
        const CERT_FUTURE        = MBEDTLS_X509_BADCERT_FUTURE;
        const CERT_KEY_USAGE     = MBEDTLS_X509_BADCERT_KEY_USAGE;
        const CERT_MISSING       = MBEDTLS_X509_BADCERT_MISSING;
        const CERT_NOT_TRUSTED   = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        const CERT_NS_CERT_TYPE  = MBEDTLS_X509_BADCERT_NS_CERT_TYPE;
        const CERT_OTHER         = MBEDTLS_X509_BADCERT_OTHER;
        const CERT_REVOKED       = MBEDTLS_X509_BADCERT_REVOKED;
        const CERT_SKIP_VERIFY   = MBEDTLS_X509_BADCERT_SKIP_VERIFY;
        const CRL_BAD_KEY        = MBEDTLS_X509_BADCRL_BAD_KEY;
        const CRL_BAD_MD         = MBEDTLS_X509_BADCRL_BAD_MD;
        const CRL_BAD_PK         = MBEDTLS_X509_BADCRL_BAD_PK;
        const CRL_EXPIRED        = MBEDTLS_X509_BADCRL_EXPIRED;
        const CRL_FUTURE         = MBEDTLS_X509_BADCRL_FUTURE;
        const CRL_NOT_TRUSTED    = MBEDTLS_X509_BADCRL_NOT_TRUSTED;
        const CUSTOM_BIT_20      = 0x10_0000;
        const CUSTOM_BIT_21      = 0x20_0000;
        const CUSTOM_BIT_22      = 0x40_0000;
        const CUSTOM_BIT_23      = 0x80_0000;
        const CUSTOM_BIT_24      = 0x100_0000;
        const CUSTOM_BIT_25      = 0x200_0000;
        const CUSTOM_BIT_26      = 0x400_0000;
        const CUSTOM_BIT_27      = 0x800_0000;
        const CUSTOM_BIT_28      = 0x1000_0000;
        const CUSTOM_BIT_29      = 0x2000_0000;
        const CUSTOM_BIT_30      = 0x4000_0000;
        const CUSTOM_BIT_31      = 0x8000_0000;
    }
}

/// A specific moment in time in UTC
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Time {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

use core::fmt::{self, Write as FmtWrite};

struct TimeWriter {
    buf: [u8; 15],
    idx: usize,
}

impl fmt::Write for TimeWriter {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        for (dst, src) in self.buf.iter_mut().skip(self.idx).zip(s.as_bytes().iter()) {
            *dst = *src
        }
        self.idx += s.len();
        Ok(())
    }

    fn write_char(&mut self, c: char) -> Result<(), fmt::Error> {
        if c >= '0' || c <= '9' {
            if let Some(dst) = self.buf.get_mut(self.idx) {
                *dst = c as u8;
                self.idx += 1;
                return Ok(());
            }
        }
        Err(fmt::Error)
    }
}

impl Time {
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Time> {
        if year < 10000
            && month >= 1
            && month <= 12
            && day >= 1
            && day <= 31
            && hour < 24
            && minute < 60
            && second < 60
        {
            Some(Time {
                year: year,
                month: month,
                day: day,
                hour: hour,
                minute: minute,
                second: second,
            })
        } else {
            None
        }
    }

    fn to_x509_time(&self) -> [u8; 15] {
        let mut writer = TimeWriter {
            buf: [0; 15],
            idx: 0,
        };
        write!(
            writer,
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
        .expect("error formatting time");
        assert!(writer.idx == 14);
        writer.buf
    }
}
