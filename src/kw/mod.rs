use crate::cipher::raw::CipherId;
use crate::error::{IntoResult, Result};

use mbedtls_sys::*;

define!(
    #[c_ty(mbedtls_nist_kw_mode_t)]
    #[derive(Copy, Clone, Eq, PartialEq)]
    enum Mode {
        KW = MBEDTLS_KW_MODE_KW,
        KWP = MBEDTLS_KW_MODE_KWP,
    }
);

impl From<mbedtls_nist_kw_mode_t> for Mode {
    fn from(inner: mbedtls_nist_kw_mode_t) -> Self {
        match inner {
            MBEDTLS_KW_MODE_KW => Mode::KW,
            MBEDTLS_KW_MODE_KWP => Mode::KWP,
            // This should be replaced with TryFrom once it is stable.
            _ => panic!("Invalid mbedtls_nist_kw_mode_t"),
        }
    }
}

define!(
    #[c_ty(mbedtls_nist_kw_context)]
    #[repr(C)]
    struct Wrapper;
    const init: fn() -> Self = mbedtls_nist_kw_init;
    const drop: fn(&mut Self) = mbedtls_nist_kw_free;
    impl<'a> Into<ptr> {}
);

impl Wrapper {
    pub fn new(cipher: CipherId, key: &[u8]) -> Result<Self> {
        let mut ctx = Wrapper::init();
        unsafe {
            mbedtls_nist_kw_setkey(
                &mut ctx.inner,
                cipher.into(),
                key.as_ptr(),
                (key.len() * 8) as _,
                1,
            )
            .into_result()
            .and(Ok(ctx))
        }
    }

    pub fn wrap(&mut self, mode: Mode, input: &[u8], output: &mut [u8]) -> Result<usize> {
        let mut len: usize = 0;

        unsafe {
            mbedtls_nist_kw_wrap(
                &mut self.inner,
                mode.into(),
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                &mut len,
                output.len(),
            )
            .into_result()
            .and(Ok(len))
        }
    }
}

define!(
    #[c_ty(mbedtls_nist_kw_context)]
    #[repr(C)]
    struct Unwrapper;
    const init: fn() -> Self = mbedtls_nist_kw_init;
    const drop: fn(&mut Self) = mbedtls_nist_kw_free;
    impl<'a> Into<ptr> {}
);

impl Unwrapper {
    pub fn new(cipher: CipherId, key: &[u8]) -> Result<Self> {
        let mut ctx = Unwrapper::init();
        unsafe {
            mbedtls_nist_kw_setkey(
                &mut ctx.inner,
                cipher.into(),
                key.as_ptr(),
                (key.len() * 8) as _,
                0,
            )
            .into_result()
            .and(Ok(ctx))
        }
    }

    pub fn unwrap(&mut self, mode: Mode, input: &[u8], output: &mut [u8]) -> Result<usize> {
        let mut len: usize = 0;

        unsafe {
            mbedtls_nist_kw_unwrap(
                &mut self.inner,
                mode.into(),
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                &mut len,
                output.len(),
            )
            .into_result()
            .and(Ok(len))
        }
    }
}

#[test]
fn aes_kw() {
    let k = [
        0x75, 0x75, 0xda, 0x3a, 0x93, 0x60, 0x7c, 0xc2, 0xbf, 0xd8, 0xce, 0xc7, 0xaa, 0xdf, 0xd9,
        0xa6,
    ];
    let p = [
        0x42, 0x13, 0x6d, 0x3c, 0x38, 0x4a, 0x3e, 0xea, 0xc9, 0x5a, 0x06, 0x6f, 0xd2, 0x8f, 0xed,
        0x3f,
    ];
    let mut p_out = [0u8; 16];
    let c = [
        0x03, 0x1f, 0x6b, 0xd7, 0xe6, 0x1e, 0x64, 0x3d, 0xf6, 0x85, 0x94, 0x81, 0x6f, 0x64, 0xca,
        0xa3, 0xf5, 0x6f, 0xab, 0xea, 0x25, 0x48, 0xf5, 0xfb,
    ];
    let mut c_out = [0u8; 24];

    let mut w = Wrapper::new(CipherId::Aes, &k).unwrap();
    w.wrap(Mode::KW, &p, &mut c_out).unwrap();
    assert_eq!(c, c_out);

    let mut u = Unwrapper::new(CipherId::Aes, &k).unwrap();
    u.unwrap(Mode::KW, &c, &mut p_out).unwrap();
    assert_eq!(p, p_out);
}

#[test]
fn aes_kwp() {
    let k = [
        0x78, 0x65, 0xe2, 0x0f, 0x3c, 0x21, 0x65, 0x9a, 0xb4, 0x69, 0x0b, 0x62, 0x9c, 0xdf, 0x3c,
        0xc4,
    ];
    let p = [0xbd, 0x68, 0x43, 0xd4, 0x20, 0x37, 0x8d, 0xc8, 0x96];
    let mut p_out = [0u8; 16];
    let c = [
        0x41, 0xec, 0xa9, 0x56, 0xd4, 0xaa, 0x04, 0x7e, 0xb5, 0xcf, 0x4e, 0xfe, 0x65, 0x96, 0x61,
        0xe7, 0x4d, 0xb6, 0xf8, 0xc5, 0x64, 0xe2, 0x35, 0x00,
    ];
    let mut c_out = [0u8; 24];

    let mut w = Wrapper::new(CipherId::Aes, &k).unwrap();
    w.wrap(Mode::KWP, &p, &mut c_out).unwrap();
    assert_eq!(c, c_out);

    let mut u = Unwrapper::new(CipherId::Aes, &k).unwrap();
    let l = u.unwrap(Mode::KWP, &c, &mut p_out).unwrap();
    assert_eq!(p, p_out[..l]);
}
