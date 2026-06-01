//! QUIC-enabled TLS 1.3 cipher suites.
//!
//! Each suite is a `rustls::Tls13CipherSuite` literal built from our [`hash`],
//! [`hkdf`], [`aead`] and [`quic`] providers, with `quic: Some(&OurAlgorithm)`
//! so rustls' QUIC machinery (including `rustls::quic::Keys::initial`) can
//! derive packet and header protection keys.
//!
//! [`hash`]: crate::hash
//! [`hkdf`]: crate::hkdf
//! [`aead`]: crate::aead
//! [`quic`]: crate::quic

use rustls::crypto::CipherSuiteCommon;
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

use crate::aead::{Tls13Aes128Gcm, Tls13Aes256Gcm, Tls13ChaCha20Poly1305};
use crate::hash;
use crate::hkdf::{HKDF_SHA256, HKDF_SHA384};
use crate::quic;

/// `TLS_AES_128_GCM_SHA256` with QUIC support (the QUIC Initial-keys suite).
static TLS13_AES_128_GCM_SHA256_INNER: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &Tls13Aes128Gcm,
    quic: Some(&quic::AES128_GCM),
};

/// `TLS_AES_256_GCM_SHA384` with QUIC support.
static TLS13_AES_256_GCM_SHA384_INNER: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: hash::SHA384,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &HKDF_SHA384,
    aead_alg: &Tls13Aes256Gcm,
    quic: Some(&quic::AES256_GCM),
};

/// `TLS_CHACHA20_POLY1305_SHA256` with QUIC support.
static TLS13_CHACHA20_POLY1305_SHA256_INNER: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &Tls13ChaCha20Poly1305,
    quic: Some(&quic::CHACHA20_POLY1305),
};

/// `TLS_AES_128_GCM_SHA256` (TLS 1.3), QUIC-enabled.
pub static TLS_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256_INNER);

/// `TLS_AES_256_GCM_SHA384` (TLS 1.3), QUIC-enabled.
pub static TLS_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&TLS13_AES_256_GCM_SHA384_INNER);

/// `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3), QUIC-enabled.
pub static TLS_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&TLS13_CHACHA20_POLY1305_SHA256_INNER);

/// All three QUIC-enabled TLS 1.3 cipher suites, in preference order.
pub static ALL_QUIC_SUITES: &[SupportedCipherSuite] = &[
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
];

/// Borrow the inner `Tls13CipherSuite` for `TLS_AES_128_GCM_SHA256`.
///
/// This is what callers pass to `rustls::quic::Keys::initial` as the `suite`
/// argument when deriving QUIC Initial keys (RFC 9001 §5.2).
#[must_use]
pub fn tls13_aes_128_gcm_sha256_internal() -> &'static Tls13CipherSuite {
    &TLS13_AES_128_GCM_SHA256_INNER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suites_have_quic_algorithm() {
        for s in ALL_QUIC_SUITES {
            match s {
                SupportedCipherSuite::Tls13(inner) => {
                    assert!(
                        inner.quic.is_some(),
                        "{:?} missing quic algorithm",
                        inner.common.suite
                    );
                }
                _ => panic!("expected TLS 1.3 suite"),
            }
        }
    }

    #[test]
    fn aes128_suite_is_initial_suite() {
        let s = tls13_aes_128_gcm_sha256_internal();
        assert_eq!(s.common.suite, CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert!(s.quic.is_some());
    }
}
