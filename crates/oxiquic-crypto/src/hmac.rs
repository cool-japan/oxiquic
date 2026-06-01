//! `rustls::crypto::hmac::Hmac` implementations for HMAC-SHA-256 and
//! HMAC-SHA-384, backed by the RustCrypto `hmac` + `sha2` crates.
//!
//! These are the foundation of the TLS 1.3 / QUIC key schedule: the rustls
//! `HkdfUsingHmac` adapter (see [`crate::hkdf`]) is built directly on top of an
//! `&'static dyn Hmac`.

use alloc::boxed::Box;

use hmac::digest::OutputSizeUser;
use hmac::{Hmac as RcHmac, KeyInit, Mac};
use rustls::crypto::hmac::{Hmac, Key, Tag};
use sha2::{Sha256, Sha384};

type HmacSha256 = RcHmac<Sha256>;
type HmacSha384 = RcHmac<Sha384>;

/// HMAC-SHA-256 provider (`rustls::crypto::hmac::Hmac`).
pub struct HmacSha256Provider;

/// The shared HMAC-SHA-256 provider instance.
pub static HMAC_SHA256: &dyn Hmac = &HmacSha256Provider;

impl Hmac for HmacSha256Provider {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        // HMAC accepts keys of *any* length (`new_from_slice` hashes oversized
        // keys and zero-pads short ones), so this only fails on a structurally
        // impossible `InvalidLength`. On that unreachable branch we fall back
        // to the infallible `KeyInit::new` over a block-sized zero key rather
        // than panicking, honouring the no-`unwrap`/`panic` policy.
        let ctx = HmacSha256::new_from_slice(key)
            .unwrap_or_else(|_| <HmacSha256 as KeyInit>::new(&Default::default()));
        Box::new(HmacSha256Key(ctx))
    }

    fn hash_output_len(&self) -> usize {
        <Sha256 as OutputSizeUser>::output_size()
    }
}

struct HmacSha256Key(HmacSha256);

impl Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        Tag::new(&ctx.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        <Sha256 as OutputSizeUser>::output_size()
    }
}

/// HMAC-SHA-384 provider (`rustls::crypto::hmac::Hmac`).
pub struct HmacSha384Provider;

/// The shared HMAC-SHA-384 provider instance.
pub static HMAC_SHA384: &dyn Hmac = &HmacSha384Provider;

impl Hmac for HmacSha384Provider {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        // See `HmacSha256Provider::with_key` for why this cannot actually fail.
        let ctx = HmacSha384::new_from_slice(key)
            .unwrap_or_else(|_| <HmacSha384 as KeyInit>::new(&Default::default()));
        Box::new(HmacSha384Key(ctx))
    }

    fn hash_output_len(&self) -> usize {
        <Sha384 as OutputSizeUser>::output_size()
    }
}

struct HmacSha384Key(HmacSha384);

impl Key for HmacSha384Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        Tag::new(&ctx.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        <Sha384 as OutputSizeUser>::output_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // RFC 4231 Test Case 2 for HMAC-SHA-256:
    // key="Jefe", data="what do ya want for nothing?"
    #[test]
    fn hmac_sha256_rfc4231_tc2() {
        let key = self::hex("4a656665");
        let data = b"what do ya want for nothing?";
        let tag = HMAC_SHA256.with_key(&key).sign(&[data]);
        assert_eq!(
            tag.as_ref(),
            &self::hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")[..]
        );
        assert_eq!(HMAC_SHA256.hash_output_len(), 32);
    }

    // RFC 4231 Test Case 2 for HMAC-SHA-384.
    #[test]
    fn hmac_sha384_rfc4231_tc2() {
        let key = self::hex("4a656665");
        let data = b"what do ya want for nothing?";
        let tag = HMAC_SHA384.with_key(&key).sign(&[data]);
        assert_eq!(
            tag.as_ref(),
            &self::hex(
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
            )[..]
        );
        assert_eq!(HMAC_SHA384.hash_output_len(), 48);
    }

    // sign_concat must equal signing the concatenation.
    #[test]
    fn sign_concat_equiv() {
        let key = b"my hmac key";
        let k = HMAC_SHA256.with_key(key);
        let concat = k.sign_concat(b"AB", &[b"CD", b"EF"], b"GH");
        let whole = k.sign(&[b"ABCDEFGH"]);
        assert_eq!(concat.as_ref(), whole.as_ref());
        assert_eq!(k.tag_len(), 32);
    }
}
