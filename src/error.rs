/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use core::str::Utf8Error;
use core::convert::Infallible;
#[cfg(feature = "std")]
use std::error::Error as StdError;

use mbedtls_sys::types::raw::c_int;

pub type Result<T> = ::core::result::Result<T, Error>;

pub trait IntoResult: Sized {
    fn into_result(self) -> Result<Self>;
    fn into_result_discard(self) -> Result<()> {
        self.into_result().map(|_| ())
    }
}

// This is intended not to overlap with mbedtls error codes. Utf8Error is
// generated in the bindings when converting to rust UTF-8 strings. Only in rare
// circumstances (callbacks from mbedtls to rust) do we need to pass a Utf8Error
// back in to mbedtls.
pub const MBEDTLS_ERR_UTF8_INVALID: c_int = -0x10000;

macro_rules! error_enum {
    {enum $n:ident {$($rust:ident = $c:ident,)*}} => {
        #[derive(Debug, Eq, PartialEq)]
        pub enum $n {
            $($rust,)*
            Other(c_int),
            Utf8Error(Option<Utf8Error>),
            // Stable-Rust equivalent of `#[non_exhaustive]` attribute. This
            // value should never be used by users of this crate!
            #[doc(hidden)]
            __Nonexhaustive,
        }

        impl IntoResult for c_int {
            fn into_result(self) -> Result<c_int> {
                let err_code = match self {
                    _ if self >= 0 => return Ok(self),
                    MBEDTLS_ERR_UTF8_INVALID => return Err(Error::Utf8Error(None)),
                    _ => -self,
                };
                let (high_level_code, low_level_code) = (err_code & 0xFF80, err_code & 0x7F);
                Err($n::from_mbedtls_code(if high_level_code > 0 { -high_level_code } else { -low_level_code }))
            }
        }

        impl $n {
            pub fn from_mbedtls_code(code: c_int) -> Self {
                match code {
                    $(::mbedtls_sys::$c => $n::$rust),*,
                    _ => $n::Other(code)
                }
            }

            pub fn as_str(&self) -> &'static str {
                match self {
                    $(&$n::$rust => concat!("mbedTLS error ",stringify!($n::$rust)),)*
                    &$n::Other(_) => "mbedTLS unknown error",
                    &$n::Utf8Error(_) => "error converting to UTF-8",
                    &$n::__Nonexhaustive => unreachable!("__Nonexhaustive value should not be instantiated"),
                }
            }

            pub fn to_int(&self) -> c_int {
                match *self {
                    $($n::$rust => ::mbedtls_sys::$c,)*
                    $n::Other(code) => code,
                    $n::Utf8Error(_) => MBEDTLS_ERR_UTF8_INVALID,
                    $n::__Nonexhaustive => unreachable!("__Nonexhaustive value should not be instantiated"),
                }
            }
        }
    };
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Error {
        Error::Utf8Error(Some(e))
    }
}

impl From<Infallible> for Error {
    fn from(x: Infallible) -> Error {
        match x {}
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Utf8Error(Some(ref e)) => {
                f.write_fmt(format_args!("Error converting to UTF-8: {}", e))
            }
            &Error::Utf8Error(None) => f.write_fmt(format_args!("Error converting to UTF-8")),
            &Error::Other(i) => f.write_fmt(format_args!("mbedTLS unknown error ({})", i)),
            &Error::__Nonexhaustive => unreachable!("__Nonexhaustive value should not be instantiated"),
            e @ _ => f.write_fmt(format_args!("mbedTLS error {:?}", e)),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Error {
    fn description(&self) -> &str {
        self.as_str()
    }
}

error_enum!(
    enum Error {
        AesBadInputData = MBEDTLS_ERR_AES_BAD_INPUT_DATA,
        AesFeatureUnavailable = MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE,
        AesHwAccelFailed = MBEDTLS_ERR_AES_HW_ACCEL_FAILED,
        AesInvalidInputLength = MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH,
        AesInvalidKeyLength = MBEDTLS_ERR_AES_INVALID_KEY_LENGTH,
        Arc4HwAccelFailed = MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED,
        AriaFeatureUnavailable = MBEDTLS_ERR_ARIA_FEATURE_UNAVAILABLE,
        AriaHwAccelFailed = MBEDTLS_ERR_ARIA_HW_ACCEL_FAILED,
        AriaInvalidInputLength = MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH,
        Asn1AllocFailed = MBEDTLS_ERR_ASN1_ALLOC_FAILED,
        Asn1BufTooSmall = MBEDTLS_ERR_ASN1_BUF_TOO_SMALL,
        Asn1InvalidData = MBEDTLS_ERR_ASN1_INVALID_DATA,
        Asn1InvalidLength = MBEDTLS_ERR_ASN1_INVALID_LENGTH,
        Asn1LengthMismatch = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH,
        Asn1OutOfData = MBEDTLS_ERR_ASN1_OUT_OF_DATA,
        Asn1UnexpectedTag = MBEDTLS_ERR_ASN1_UNEXPECTED_TAG,
        Base64BufferTooSmall = MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL,
        Base64InvalidCharacter = MBEDTLS_ERR_BASE64_INVALID_CHARACTER,
        BlowfishHwAccelFailed = MBEDTLS_ERR_BLOWFISH_HW_ACCEL_FAILED,
        BlowfishInvalidInputLength = MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH,
        CamelliaHwAccelFailed = MBEDTLS_ERR_CAMELLIA_HW_ACCEL_FAILED,
        CamelliaInvalidInputLength = MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH,
        CcmAuthFailed = MBEDTLS_ERR_CCM_AUTH_FAILED,
        CcmBadInput = MBEDTLS_ERR_CCM_BAD_INPUT,
        CcmHwAccelFailed = MBEDTLS_ERR_CCM_HW_ACCEL_FAILED,
        Chacha20BadInputData = MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA,
        Chacha20FeatureUnavailable = MBEDTLS_ERR_CHACHA20_FEATURE_UNAVAILABLE,
        Chacha20HwAccelFailed = MBEDTLS_ERR_CHACHA20_HW_ACCEL_FAILED,
        ChachapolyAuthFailed = MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED,
        ChachapolyBadState = MBEDTLS_ERR_CHACHAPOLY_BAD_STATE,
        CipherAllocFailed = MBEDTLS_ERR_CIPHER_ALLOC_FAILED,
        CipherAuthFailed = MBEDTLS_ERR_CIPHER_AUTH_FAILED,
        CipherBadInputData = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA,
        CipherFeatureUnavailable = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE,
        CipherFullBlockExpected = MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED,
        CipherHwAccelFailed = MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED,
        CipherInvalidContext = MBEDTLS_ERR_CIPHER_INVALID_CONTEXT,
        CipherInvalidPadding = MBEDTLS_ERR_CIPHER_INVALID_PADDING,
        CmacHwAccelFailed = MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED,
        CtrDrbgEntropySourceFailed = MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED,
        CtrDrbgFileIoError = MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR,
        CtrDrbgInputTooBig = MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG,
        CtrDrbgRequestTooBig = MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG,
        DesHwAccelFailed = MBEDTLS_ERR_DES_HW_ACCEL_FAILED,
        DesInvalidInputLength = MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH,
        DhmAllocFailed = MBEDTLS_ERR_DHM_ALLOC_FAILED,
        DhmBadInputData = MBEDTLS_ERR_DHM_BAD_INPUT_DATA,
        DhmCalcSecretFailed = MBEDTLS_ERR_DHM_CALC_SECRET_FAILED,
        DhmFileIoError = MBEDTLS_ERR_DHM_FILE_IO_ERROR,
        DhmHwAccelFailed = MBEDTLS_ERR_DHM_HW_ACCEL_FAILED,
        DhmInvalidFormat = MBEDTLS_ERR_DHM_INVALID_FORMAT,
        DhmMakeParamsFailed = MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED,
        DhmMakePublicFailed = MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED,
        DhmReadParamsFailed = MBEDTLS_ERR_DHM_READ_PARAMS_FAILED,
        DhmReadPublicFailed = MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED,
        DhmSetGroupFailed = MBEDTLS_ERR_DHM_SET_GROUP_FAILED,
        EcpAllocFailed = MBEDTLS_ERR_ECP_ALLOC_FAILED,
        EcpBadInputData = MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
        EcpBufferTooSmall = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL,
        EcpFeatureUnavailable = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE,
        EcpHwAccelFailed = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED,
        EcpInvalidKey = MBEDTLS_ERR_ECP_INVALID_KEY,
        EcpRandomFailed = MBEDTLS_ERR_ECP_RANDOM_FAILED,
        EcpSigLenMismatch = MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH,
        EcpVerifyFailed = MBEDTLS_ERR_ECP_VERIFY_FAILED,
        EntropyFileIoError = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR,
        EntropyMaxSources = MBEDTLS_ERR_ENTROPY_MAX_SOURCES,
        EntropyNoSourcesDefined = MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED,
        EntropyNoStrongSource = MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE,
        EntropySourceFailed = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED,
        GcmAuthFailed = MBEDTLS_ERR_GCM_AUTH_FAILED,
        GcmBadInput = MBEDTLS_ERR_GCM_BAD_INPUT,
        GcmHwAccelFailed = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED,
        HkdfBadInputData = MBEDTLS_ERR_HKDF_BAD_INPUT_DATA,
        HmacDrbgEntropySourceFailed = MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED,
        HmacDrbgFileIoError = MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR,
        HmacDrbgInputTooBig = MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG,
        HmacDrbgRequestTooBig = MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG,
        Md2HwAccelFailed = MBEDTLS_ERR_MD2_HW_ACCEL_FAILED,
        Md4HwAccelFailed = MBEDTLS_ERR_MD4_HW_ACCEL_FAILED,
        Md5HwAccelFailed = MBEDTLS_ERR_MD5_HW_ACCEL_FAILED,
        MdAllocFailed = MBEDTLS_ERR_MD_ALLOC_FAILED,
        MdBadInputData = MBEDTLS_ERR_MD_BAD_INPUT_DATA,
        MdFeatureUnavailable = MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE,
        MdFileIoError = MBEDTLS_ERR_MD_FILE_IO_ERROR,
        MdHwAccelFailed = MBEDTLS_ERR_MD_HW_ACCEL_FAILED,
        MpiAllocFailed = MBEDTLS_ERR_MPI_ALLOC_FAILED,
        MpiBadInputData = MBEDTLS_ERR_MPI_BAD_INPUT_DATA,
        MpiBufferTooSmall = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL,
        MpiDivisionByZero = MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
        MpiFileIoError = MBEDTLS_ERR_MPI_FILE_IO_ERROR,
        MpiInvalidCharacter = MBEDTLS_ERR_MPI_INVALID_CHARACTER,
        MpiNegativeValue = MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
        MpiNotAcceptable = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE,
        NetAcceptFailed = MBEDTLS_ERR_NET_ACCEPT_FAILED,
        NetBadInputData = MBEDTLS_ERR_NET_BAD_INPUT_DATA,
        NetBindFailed = MBEDTLS_ERR_NET_BIND_FAILED,
        NetBufferTooSmall = MBEDTLS_ERR_NET_BUFFER_TOO_SMALL,
        NetConnReset = MBEDTLS_ERR_NET_CONN_RESET,
        NetConnectFailed = MBEDTLS_ERR_NET_CONNECT_FAILED,
        NetInvalidContext = MBEDTLS_ERR_NET_INVALID_CONTEXT,
        NetListenFailed = MBEDTLS_ERR_NET_LISTEN_FAILED,
        NetPollFailed = MBEDTLS_ERR_NET_POLL_FAILED,
        NetRecvFailed = MBEDTLS_ERR_NET_RECV_FAILED,
        NetSendFailed = MBEDTLS_ERR_NET_SEND_FAILED,
        NetSocketFailed = MBEDTLS_ERR_NET_SOCKET_FAILED,
        NetUnknownHost = MBEDTLS_ERR_NET_UNKNOWN_HOST,
        OidBufTooSmall = MBEDTLS_ERR_OID_BUF_TOO_SMALL,
        OidNotFound = MBEDTLS_ERR_OID_NOT_FOUND,
        PadlockDataMisaligned = MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED,
        PemAllocFailed = MBEDTLS_ERR_PEM_ALLOC_FAILED,
        PemBadInputData = MBEDTLS_ERR_PEM_BAD_INPUT_DATA,
        PemFeatureUnavailable = MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE,
        PemInvalidData = MBEDTLS_ERR_PEM_INVALID_DATA,
        PemInvalidEncIv = MBEDTLS_ERR_PEM_INVALID_ENC_IV,
        PemNoHeaderFooterPresent = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT,
        PemPasswordMismatch = MBEDTLS_ERR_PEM_PASSWORD_MISMATCH,
        PemPasswordRequired = MBEDTLS_ERR_PEM_PASSWORD_REQUIRED,
        PemUnknownEncAlg = MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG,
        PkAllocFailed = MBEDTLS_ERR_PK_ALLOC_FAILED,
        PkBadInputData = MBEDTLS_ERR_PK_BAD_INPUT_DATA,
        PkFeatureUnavailable = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE,
        PkFileIoError = MBEDTLS_ERR_PK_FILE_IO_ERROR,
        PkHwAccelFailed = MBEDTLS_ERR_PK_HW_ACCEL_FAILED,
        PkInvalidAlg = MBEDTLS_ERR_PK_INVALID_ALG,
        PkInvalidPubkey = MBEDTLS_ERR_PK_INVALID_PUBKEY,
        PkKeyInvalidFormat = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
        PkKeyInvalidVersion = MBEDTLS_ERR_PK_KEY_INVALID_VERSION,
        PkPasswordMismatch = MBEDTLS_ERR_PK_PASSWORD_MISMATCH,
        PkPasswordRequired = MBEDTLS_ERR_PK_PASSWORD_REQUIRED,
        PkSigLenMismatch = MBEDTLS_ERR_PK_SIG_LEN_MISMATCH,
        PkTypeMismatch = MBEDTLS_ERR_PK_TYPE_MISMATCH,
        PkUnknownNamedCurve = MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE,
        PkUnknownPkAlg = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG,
        Pkcs12BadInputData = MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA,
        Pkcs12FeatureUnavailable = MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE,
        Pkcs12PasswordMismatch = MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH,
        Pkcs12PbeInvalidFormat = MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT,
        Pkcs5BadInputData = MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA,
        Pkcs5FeatureUnavailable = MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE,
        Pkcs5InvalidFormat = MBEDTLS_ERR_PKCS5_INVALID_FORMAT,
        Pkcs5PasswordMismatch = MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH,
        Poly1305BadInputData = MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA,
        Poly1305FeatureUnavailable = MBEDTLS_ERR_POLY1305_FEATURE_UNAVAILABLE,
        Poly1305HwAccelFailed = MBEDTLS_ERR_POLY1305_HW_ACCEL_FAILED,
        Ripemd160HwAccelFailed = MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED,
        RsaBadInputData = MBEDTLS_ERR_RSA_BAD_INPUT_DATA,
        RsaHwAccelFailed = MBEDTLS_ERR_RSA_HW_ACCEL_FAILED,
        RsaInvalidPadding = MBEDTLS_ERR_RSA_INVALID_PADDING,
        RsaKeyCheckFailed = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED,
        RsaKeyGenFailed = MBEDTLS_ERR_RSA_KEY_GEN_FAILED,
        RsaOutputTooLarge = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE,
        RsaPrivateFailed = MBEDTLS_ERR_RSA_PRIVATE_FAILED,
        RsaPublicFailed = MBEDTLS_ERR_RSA_PUBLIC_FAILED,
        RsaRngFailed = MBEDTLS_ERR_RSA_RNG_FAILED,
        RsaUnsupportedOperation = MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION,
        RsaVerifyFailed = MBEDTLS_ERR_RSA_VERIFY_FAILED,
        Sha1HwAccelFailed = MBEDTLS_ERR_SHA1_HW_ACCEL_FAILED,
        Sha256HwAccelFailed = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED,
        Sha512HwAccelFailed = MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED,
        SslAllocFailed = MBEDTLS_ERR_SSL_ALLOC_FAILED,
        SslAsyncInProgress = MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS,
        SslBadHsCertificate = MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE,
        SslBadHsCertificateRequest = MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST,
        SslBadHsCertificateVerify = MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY,
        SslBadHsChangeCipherSpec = MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC,
        SslBadHsClientHello = MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO,
        SslBadHsClientKeyExchange = MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE,
        SslBadHsClientKeyExchangeCs = MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS,
        SslBadHsClientKeyExchangeRp = MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP,
        SslBadHsFinished = MBEDTLS_ERR_SSL_BAD_HS_FINISHED,
        SslBadHsNewSessionTicket = MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET,
        SslBadHsProtocolVersion = MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION,
        SslBadHsServerHello = MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO,
        SslBadHsServerHelloDone = MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE,
        SslBadHsServerKeyExchange = MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE,
        SslBadInputData = MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
        SslBufferTooSmall = MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL,
        SslCaChainRequired = MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED,
        SslCertificateRequired = MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED,
        SslCertificateTooLarge = MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE,
        SslClientReconnect = MBEDTLS_ERR_SSL_CLIENT_RECONNECT,
        SslCompressionFailed = MBEDTLS_ERR_SSL_COMPRESSION_FAILED,
        SslConnEof = MBEDTLS_ERR_SSL_CONN_EOF,
        SslContinueProcessing = MBEDTLS_ERR_SSL_CONTINUE_PROCESSING,
        SslCounterWrapping = MBEDTLS_ERR_SSL_COUNTER_WRAPPING,
        SslFatalAlertMessage = MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE,
        SslFeatureUnavailable = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE,
        SslHelloVerifyRequired = MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED,
        SslHwAccelFailed = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED,
        SslHwAccelFallthrough = MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH,
        SslInternalError = MBEDTLS_ERR_SSL_INTERNAL_ERROR,
        SslInvalidMac = MBEDTLS_ERR_SSL_INVALID_MAC,
        SslInvalidRecord = MBEDTLS_ERR_SSL_INVALID_RECORD,
        SslInvalidVerifyHash = MBEDTLS_ERR_SSL_INVALID_VERIFY_HASH,
        SslNoCipherChosen = MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN,
        SslNoClientCertificate = MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE,
        SslNoRng = MBEDTLS_ERR_SSL_NO_RNG,
        SslNoUsableCiphersuite = MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE,
        SslNonFatal = MBEDTLS_ERR_SSL_NON_FATAL,
        SslPeerCloseNotify = MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY,
        SslPeerVerifyFailed = MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED,
        SslPkTypeMismatch = MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH,
        SslPrivateKeyRequired = MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED,
        SslSessionTicketExpired = MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED,
        SslTimeout = MBEDTLS_ERR_SSL_TIMEOUT,
        SslUnexpectedMessage = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE,
        SslUnexpectedRecord = MBEDTLS_ERR_SSL_UNEXPECTED_RECORD,
        SslUnknownCipher = MBEDTLS_ERR_SSL_UNKNOWN_CIPHER,
        SslUnknownIdentity = MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY,
        SslWaitingServerHelloRenego = MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO,
        SslWantRead = MBEDTLS_ERR_SSL_WANT_READ,
        SslWantWrite = MBEDTLS_ERR_SSL_WANT_WRITE,
        X509AllocFailed = MBEDTLS_ERR_X509_ALLOC_FAILED,
        X509BadInputData = MBEDTLS_ERR_X509_BAD_INPUT_DATA,
        X509BufferTooSmall = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL,
        X509CertUnknownFormat = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT,
        X509CertVerifyFailed = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
        X509FatalError = MBEDTLS_ERR_X509_FATAL_ERROR,
        X509FeatureUnavailable = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE,
        X509FileIoError = MBEDTLS_ERR_X509_FILE_IO_ERROR,
        X509InvalidAlg = MBEDTLS_ERR_X509_INVALID_ALG,
        X509InvalidDate = MBEDTLS_ERR_X509_INVALID_DATE,
        X509InvalidExtensions = MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
        X509InvalidFormat = MBEDTLS_ERR_X509_INVALID_FORMAT,
        X509InvalidName = MBEDTLS_ERR_X509_INVALID_NAME,
        X509InvalidSerial = MBEDTLS_ERR_X509_INVALID_SERIAL,
        X509InvalidSignature = MBEDTLS_ERR_X509_INVALID_SIGNATURE,
        X509InvalidVersion = MBEDTLS_ERR_X509_INVALID_VERSION,
        X509SigMismatch = MBEDTLS_ERR_X509_SIG_MISMATCH,
        X509UnknownOid = MBEDTLS_ERR_X509_UNKNOWN_OID,
        X509UnknownSigAlg = MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG,
        X509UnknownVersion = MBEDTLS_ERR_X509_UNKNOWN_VERSION,
        XteaHwAccelFailed = MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED,
        XteaInvalidInputLength = MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH,
    }
);
