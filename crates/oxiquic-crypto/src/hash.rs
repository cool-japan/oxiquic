//! `rustls::crypto::hash::Hash` implementations for SHA-256 and SHA-384,
//! backed by the RustCrypto `sha2` crate (the same crate OxiCrypto uses).
//!
//! rustls needs both one-shot ([`Hash::hash`]) and incremental
//! ([`Hash::start`] -> [`Context`]) hashing for the TLS 1.3 transcript.

use alloc::boxed::Box;

use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use sha2::digest::Digest;
use sha2::{Sha256, Sha384};

/// SHA-256 hash provider (`rustls::crypto::hash::Hash`).
pub struct Sha256Hash;

/// The shared SHA-256 hash provider instance.
pub static SHA256: &dyn Hash = &Sha256Hash;

impl Hash for Sha256Hash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha256Context(Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&Sha256::digest(data)[..])
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
}

struct Sha256Context(Sha256);

impl Context for Sha256Context {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

/// SHA-384 hash provider (`rustls::crypto::hash::Hash`).
pub struct Sha384Hash;

/// The shared SHA-384 hash provider instance.
pub static SHA384: &dyn Hash = &Sha384Hash;

impl Hash for Sha384Hash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha384Context(Sha384::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&Sha384::digest(data)[..])
    }

    fn output_len(&self) -> usize {
        48
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }
}

struct Sha384Context(Sha384);

impl Context for Sha384Context {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha384Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        // FIPS 180-4 SHA-256("abc")
        let out = SHA256.hash(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(out.as_ref(), &expected);
        assert_eq!(SHA256.output_len(), 32);
        assert_eq!(SHA256.algorithm(), HashAlgorithm::SHA256);
    }

    #[test]
    fn sha384_incremental_matches_oneshot() {
        let mut ctx = SHA384.start();
        ctx.update(b"ab");
        ctx.update(b"c");
        let inc = ctx.finish();
        let one = SHA384.hash(b"abc");
        assert_eq!(inc.as_ref(), one.as_ref());
        assert_eq!(SHA384.output_len(), 48);
        assert_eq!(SHA384.algorithm(), HashAlgorithm::SHA384);
    }

    #[test]
    fn sha256_fork_preserves_prefix() {
        let mut ctx = SHA256.start();
        ctx.update(b"hello");
        let forked = ctx.fork_finish();
        // forked == hash("hello"); continuing the original still works
        assert_eq!(forked.as_ref(), SHA256.hash(b"hello").as_ref());
        ctx.update(b" world");
        assert_eq!(ctx.finish().as_ref(), SHA256.hash(b"hello world").as_ref());
    }
}
