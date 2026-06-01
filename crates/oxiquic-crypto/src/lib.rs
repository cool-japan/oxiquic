#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! `oxiquic-crypto` — the Pure-Rust rustls ↔ OxiCrypto bridge for QUIC.
//!
//! This crate implements the [`rustls`] crypto-provider traits over
//! [`oxicrypto`] (and the same RustCrypto primitives OxiCrypto wraps), adds
//! QUIC packet/header protection (RFC 9001 §5), and assembles a
//! [`CryptoProvider`] whose TLS 1.3 cipher
//! suites are **QUIC-enabled** (`quic: Some(..)`). The COOLJAPAN Pure-Rust
//! policy forbids `ring` / `aws-lc-rs` / `openssl`; nothing here pulls them in.
//!
//! # What it provides
//!
//! | rustls trait | Implemented for | Module |
//! |--------------|-----------------|--------|
//! | [`crypto::hash::Hash`](rustls::crypto::hash::Hash) | SHA-256, SHA-384 | [`hash`] |
//! | [`crypto::hmac::Hmac`](rustls::crypto::hmac::Hmac) | HMAC-SHA-256/384 | [`hmac`] |
//! | [`crypto::tls13::Hkdf`](rustls::crypto::tls13::Hkdf) | SHA-256/384 (via `HkdfUsingHmac`) | [`hkdf`] |
//! | [`crypto::cipher::Tls13AeadAlgorithm`](rustls::crypto::cipher::Tls13AeadAlgorithm) | AES-128/256-GCM, ChaCha20-Poly1305 | [`aead`] |
//! | [`quic::Algorithm`](rustls::quic::Algorithm) + [`PacketKey`](rustls::quic::PacketKey) + [`HeaderProtectionKey`](rustls::quic::HeaderProtectionKey) | all three suites | [`quic`] |
//!
//! # Entry points
//!
//! * [`quic_crypto_provider`] — a [`CryptoProvider`]
//!   with the three QUIC-enabled suites, reusing
//!   [`rustls_rustcrypto::provider`]'s key exchange, signature verification,
//!   secure random and key provider.
//! * [`suites`] — the three `&'static SupportedCipherSuite` constants and the
//!   inner `Tls13CipherSuite` needed for [`rustls::quic::Keys::initial`].
//!
//! # QUIC Initial keys (RFC 9001 §5.2) — routing
//!
//! `rustls::quic::Keys::initial(version, suite, quic_alg, dcid, side)` derives
//! Initial keys entirely through `suite.hkdf_provider` and the `quic`
//! [`Algorithm`](rustls::quic::Algorithm) — both of which are *ours* here. The
//! version salt is a rustls constant. There is therefore **no** independent
//! ring/aws-lc derivation path: Wave 2 obtains Initial keys with
//!
//! ```no_run
//! use oxiquic_crypto::suites::{tls13_aes_128_gcm_sha256_internal};
//! use oxiquic_crypto::quic::AES128_GCM;
//! use rustls::quic::{Keys, Version};
//! use rustls::Side;
//!
//! let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
//! let keys = Keys::initial(
//!     Version::V1,
//!     tls13_aes_128_gcm_sha256_internal(),
//!     &AES128_GCM,
//!     &dcid,
//!     Side::Client,
//! );
//! # let _ = keys;
//! ```

extern crate alloc;

use alloc::vec::Vec;

use rustls::crypto::CryptoProvider;

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod quic;
pub mod suites;

/// Build a [`CryptoProvider`] whose TLS 1.3 cipher suites are QUIC-enabled.
///
/// The returned provider keeps `rustls_rustcrypto::provider()`'s key-exchange
/// groups, signature-verification algorithms, secure random source and key
/// provider, but replaces the cipher suites with the three QUIC-capable suites
/// from [`suites`] (`quic: Some(..)`), so a `rustls::quic::ClientConnection` /
/// `ServerConnection` built from this provider can complete a handshake and
/// derive packet keys. No `ring` / `aws-lc-rs` is involved.
///
/// # Example
/// ```
/// let provider = oxiquic_crypto::quic_crypto_provider();
/// assert_eq!(provider.cipher_suites.len(), 3);
/// ```
#[must_use]
pub fn quic_crypto_provider() -> CryptoProvider {
    let base = rustls_rustcrypto::provider();
    CryptoProvider {
        cipher_suites: suites::ALL_QUIC_SUITES.to_vec(),
        kx_groups: base.kx_groups,
        signature_verification_algorithms: base.signature_verification_algorithms,
        secure_random: base.secure_random,
        key_provider: base.key_provider,
    }
}

/// The three QUIC-enabled TLS 1.3 cipher suites (convenience re-export of
/// [`suites::ALL_QUIC_SUITES`] as an owned `Vec`).
#[must_use]
pub fn all_quic_cipher_suites() -> Vec<rustls::SupportedCipherSuite> {
    suites::ALL_QUIC_SUITES.to_vec()
}

/// Returns the Pure-Rust [`CryptoProvider`] from the oxitls facade.
///
/// This is the provider returned by [`oxitls::quic_preview::pure_quic_provider()`]
/// — essentially `rustls_rustcrypto::provider()` wrapped in an `Arc`.
///
/// # Limitation
///
/// The cipher suites in this provider have `quic: None`; they are **not**
/// suitable for deriving QUIC packet/header-protection keys.  For actual QUIC
/// connections use the default [`quic_crypto_provider()`] instead, whose suites
/// have `quic: Some(..)` wired to the oxiquic AEAD/HKDF implementations.
///
/// This function exists as an additive, feature-gated hook so oxiquic can
/// expose the oxitls provider to callers that want a unified "Pure-Rust
/// CryptoProvider from oxitls" without importing the oxitls crate directly.
///
/// # Example
/// ```
/// # #[cfg(feature = "oxitls-provider")]
/// # {
/// let p = oxiquic_crypto::oxitls_quic_provider();
/// assert!(!p.cipher_suites.is_empty());
/// assert!(!p.kx_groups.is_empty());
/// # }
/// ```
#[cfg(feature = "oxitls-provider")]
#[must_use]
pub fn oxitls_quic_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    oxitls::quic_preview::pure_quic_provider()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_has_three_quic_suites() {
        let p = quic_crypto_provider();
        assert_eq!(p.cipher_suites.len(), 3);
        for s in &p.cipher_suites {
            match s {
                rustls::SupportedCipherSuite::Tls13(inner) => assert!(inner.quic.is_some()),
                _ => panic!("non-TLS1.3 suite in QUIC provider"),
            }
        }
        // kx / sig / rng / key provider are inherited (non-empty).
        assert!(!p.kx_groups.is_empty());
        assert!(!p.signature_verification_algorithms.all.is_empty());
    }

    /// Smoke-test: oxitls_quic_provider() compiles, returns a non-empty provider,
    /// and has Pure-Rust lineage (no ring/aws-lc-rs).
    ///
    /// Note: the returned suites have `quic: None` — this is expected and
    /// documented.  For QUIC packet-key derivation use `quic_crypto_provider()`.
    #[cfg(feature = "oxitls-provider")]
    #[test]
    fn oxitls_provider_is_non_null() {
        let p = oxitls_quic_provider();
        assert!(
            !p.cipher_suites.is_empty(),
            "oxitls provider has no cipher suites"
        );
        assert!(!p.kx_groups.is_empty(), "oxitls provider has no kx groups");
        // Confirm the suites come from plain rustls-rustcrypto (quic: None).
        for s in &p.cipher_suites {
            if let rustls::SupportedCipherSuite::Tls13(inner) = s {
                assert!(
                    inner.quic.is_none(),
                    "expected quic: None on oxitls-sourced suites (they are not QUIC-enabled)"
                );
            }
        }
    }
}
