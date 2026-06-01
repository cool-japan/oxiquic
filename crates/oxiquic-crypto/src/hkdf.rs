//! `rustls::crypto::tls13::Hkdf` providers for the TLS 1.3 / QUIC key schedule.
//!
//! rustls ships a generic [`HkdfUsingHmac`] adapter that implements the full
//! `Hkdf` trait (extract / expand / expand-label) on top of any
//! `&'static dyn rustls::crypto::hmac::Hmac`. We simply instantiate it with our
//! [`crate::hmac`] providers, so the QUIC key schedule (including
//! `rustls::quic::Keys::initial`) runs entirely on OxiCrypto-equivalent
//! RustCrypto primitives.

use rustls::crypto::tls13::{Hkdf, HkdfUsingHmac};

use crate::hmac::{HMAC_SHA256, HMAC_SHA384};

/// HKDF-SHA-256 provider for TLS 1.3 / QUIC (`rustls::crypto::tls13::Hkdf`).
pub static HKDF_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(HMAC_SHA256);

/// HKDF-SHA-384 provider for TLS 1.3 / QUIC (`rustls::crypto::tls13::Hkdf`).
pub static HKDF_SHA384: HkdfUsingHmac<'static> = HkdfUsingHmac(HMAC_SHA384);

/// Borrow [`HKDF_SHA256`] as a `&'static dyn Hkdf` (convenience for cipher-suite
/// construction).
#[must_use]
pub fn hkdf_sha256() -> &'static dyn Hkdf {
    &HKDF_SHA256
}

/// Borrow [`HKDF_SHA384`] as a `&'static dyn Hkdf`.
#[must_use]
pub fn hkdf_sha384() -> &'static dyn Hkdf {
    &HKDF_SHA384
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::tls13::{expand, OkmBlock};

    struct Bytes<const N: usize>([u8; N]);
    impl<const N: usize> From<[u8; N]> for Bytes<N> {
        fn from(a: [u8; N]) -> Self {
            Self(a)
        }
    }

    // RFC 5869 Test Case 1 driven through rustls' Hkdf trait on our HMAC.
    #[test]
    fn hkdf_sha256_rfc5869_tc1() {
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: &[&[u8]] = &[
            &[0xf0, 0xf1, 0xf2],
            &[0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        ];
        let out: Bytes<42> = expand(
            HKDF_SHA256.extract_from_secret(Some(&salt), &ikm).as_ref(),
            info,
        );
        assert_eq!(
            &out.0,
            &[
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }

    // The QUIC initial-secret extraction (RFC 9001 §A.1) through rustls' Hkdf.
    #[test]
    fn quic_initial_secret_extract() {
        const SALT: &[u8] = &[
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];
        const DCID: &[u8] = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let expander = HKDF_SHA256.extract_from_secret(Some(SALT), DCID);
        // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
        // HkdfLabel for "client in" length 32:
        //   00 20 | 0f | "tls13 client in" | 00
        let label: &[&[u8]] = &[&[0x00, 0x20], &[0x0f], b"tls13 client in", &[0x00]];
        let secret: OkmBlock = expander.expand_block(label);
        assert_eq!(
            secret.as_ref(),
            &[
                0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03,
                0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f,
                0x6c, 0x35, 0x7a, 0xea,
            ]
        );
    }
}
