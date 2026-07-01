//! `rustls::crypto::cipher::Tls13AeadAlgorithm` implementations for the three
//! QUIC/TLS 1.3 AEADs: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
//!
//! These mirror the structure of the `rustls-rustcrypto` provider (the AEADs
//! themselves are the same RustCrypto crates OxiCrypto wraps), with two
//! deliberate differences:
//!
//! 1. **Correct `extract_keys` variant** — `rustls-rustcrypto` returns
//!    `ConnectionTrafficSecrets::Aes256Gcm` for *both* AES suites; we return the
//!    matching variant per key size.
//! 2. **No panics** — key construction failures (structurally impossible, since
//!    rustls always hands us a `key_len()`-sized key) degrade to an AEAD that
//!    reports `EncryptError` / `DecryptError` instead of `expect()`-panicking.

use alloc::boxed::Box;

use aead::{AeadInOut, Buffer, KeyInit};
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage, Iv,
    MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

/// All TLS 1.3 / QUIC AEADs here use a 16-byte authentication tag.
const TAG_LEN: usize = 16;

// ── Buffer adapters bridging rustls payload types to `aead::Buffer` ──────────

struct EncryptBufferAdapter<'a>(&'a mut PrefixedPayload);

impl AsRef<[u8]> for EncryptBufferAdapter<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for EncryptBufferAdapter<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Buffer for EncryptBufferAdapter<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

struct DecryptBufferAdapter<'a, 'p>(&'a mut BorrowedPayload<'p>);

impl AsRef<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl AsMut<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Buffer for DecryptBufferAdapter<'_, '_> {
    fn extend_from_slice(&mut self, _: &[u8]) -> aead::Result<()> {
        // `AeadInOut::decrypt_in_place` only ever truncates.
        Err(aead::Error)
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

// ── Generic TLS 1.3 cipher over any `aead` AEAD ──────────────────────────────

/// A TLS 1.3 record encrypter/decrypter: an optional AEAD instance plus the IV.
///
/// The AEAD is `Option` so that a key-construction failure (which cannot occur
/// for a correctly sized key) yields encrypt/decrypt errors rather than a
/// panic.
struct Tls13Cipher<A: AeadInOut> {
    aead: Option<A>,
    iv: Iv,
}

impl<A> MessageEncrypter for Tls13Cipher<A>
where
    A: AeadInOut + Send + Sync,
{
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let aead = self.aead.as_ref().ok_or(Error::EncryptError)?;
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce = aead::Nonce::<A>::try_from(Nonce::new(&self.iv, seq).0.as_slice())
            .map_err(|_| Error::EncryptError)?;
        let aad = make_tls13_aad(total_len);

        aead.encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| Error::EncryptError)?;
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        // payload + content-type byte + AEAD tag
        payload_len + 1 + TAG_LEN
    }
}

impl<A> MessageDecrypter for Tls13Cipher<A>
where
    A: AeadInOut + Send + Sync,
{
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let aead = self.aead.as_ref().ok_or(Error::DecryptError)?;
        let payload = &mut m.payload;
        let nonce = aead::Nonce::<A>::try_from(Nonce::new(&self.iv, seq).0.as_slice())
            .map_err(|_| Error::DecryptError)?;
        let aad = make_tls13_aad(payload.len());

        aead.decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| Error::DecryptError)?;

        m.into_tls13_unpadded_message()
    }
}

// ── AES-128-GCM ──────────────────────────────────────────────────────────────

/// AES-128-GCM TLS 1.3 AEAD algorithm.
pub struct Tls13Aes128Gcm;

impl Tls13AeadAlgorithm for Tls13Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher::<aes_gcm::Aes128Gcm> {
            aead: new_aead(key.as_ref()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher::<aes_gcm::Aes128Gcm> {
            aead: new_aead(key.as_ref()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

// ── AES-256-GCM ──────────────────────────────────────────────────────────────

/// AES-256-GCM TLS 1.3 AEAD algorithm.
pub struct Tls13Aes256Gcm;

impl Tls13AeadAlgorithm for Tls13Aes256Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher::<aes_gcm::Aes256Gcm> {
            aead: new_aead(key.as_ref()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher::<aes_gcm::Aes256Gcm> {
            aead: new_aead(key.as_ref()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }
}

// ── ChaCha20-Poly1305 ────────────────────────────────────────────────────────

/// ChaCha20-Poly1305 TLS 1.3 AEAD algorithm.
pub struct Tls13ChaCha20Poly1305;

impl Tls13AeadAlgorithm for Tls13ChaCha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher::<chacha20poly1305::ChaCha20Poly1305> {
            aead: new_aead(key.as_ref()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher::<chacha20poly1305::ChaCha20Poly1305> {
            aead: new_aead(key.as_ref()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

/// Construct an AEAD from a key slice, returning `None` on the (structurally
/// impossible) length mismatch so callers can degrade to an error rather than
/// panic.
fn new_aead<A: KeyInit>(key: &[u8]) -> Option<A> {
    A::new_from_slice(key).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A TLS 1.3 record encrypted then decrypted through the rustls traits must
    // round-trip. `AeadKey::from([u8; 32])` is the only public constructor, so
    // we exercise the 32-byte-key AEADs here (AES-256-GCM, ChaCha20-Poly1305).
    // The AES-128 path is exercised end-to-end by the QUIC initial-key vectors
    // (RFC 9001 §A.2/§A.3) and the in-memory handshake, where rustls builds the
    // 16-byte key internally.
    fn round_trip_32(alg: &dyn Tls13AeadAlgorithm) {
        let mut enc = alg.encrypter(AeadKey::from([0x2a_u8; 32]), Iv::from([0x11_u8; 12]));
        let mut dec = alg.decrypter(AeadKey::from([0x2a_u8; 32]), Iv::from([0x11_u8; 12]));

        let plaintext = b"oxiquic tls13 record payload";
        let chunks = [&plaintext[..]];
        let out_msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: rustls::crypto::cipher::OutboundChunks::new(&chunks),
        };
        let opaque = enc.encrypt(out_msg, 0).expect("encrypt");
        let enc_bytes = opaque.encode();

        // Strip the 5-byte record header to feed the decrypter.
        let mut body = enc_bytes[5..].to_vec();
        let in_msg = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut body,
        );
        let plain = dec.decrypt(in_msg, 0).expect("decrypt");
        assert_eq!(plain.payload, plaintext);
    }

    #[test]
    fn aes256gcm_round_trip() {
        round_trip_32(&Tls13Aes256Gcm);
    }

    #[test]
    fn chacha20_round_trip() {
        round_trip_32(&Tls13ChaCha20Poly1305);
    }

    #[test]
    fn wrong_seq_fails_auth() {
        // Decrypting with a mismatched sequence number must fail (AEAD auth).
        let mut enc =
            Tls13ChaCha20Poly1305.encrypter(AeadKey::from([7u8; 32]), Iv::from([3u8; 12]));
        let mut dec =
            Tls13ChaCha20Poly1305.decrypter(AeadKey::from([7u8; 32]), Iv::from([3u8; 12]));
        let pt = b"authenticate me";
        let chunks = [&pt[..]];
        let opaque = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_3,
                    payload: rustls::crypto::cipher::OutboundChunks::new(&chunks),
                },
                0,
            )
            .expect("encrypt");
        let mut body = opaque.encode()[5..].to_vec();
        let in_msg = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut body,
        );
        assert!(dec.decrypt(in_msg, 1).is_err());
    }

    #[test]
    fn key_len_values() {
        assert_eq!(Tls13Aes128Gcm.key_len(), 16);
        assert_eq!(Tls13Aes256Gcm.key_len(), 32);
        assert_eq!(Tls13ChaCha20Poly1305.key_len(), 32);
    }

    #[test]
    fn extract_keys_correct_variant() {
        // AES-256 and ChaCha20 map to their matching variants. (AES-128's
        // Aes128Gcm mapping cannot be built with a 32-byte public key here;
        // it is covered by the handshake test which negotiates AES-128-GCM.)
        match Tls13Aes256Gcm.extract_keys(AeadKey::from([0u8; 32]), Iv::from([0u8; 12])) {
            Ok(ConnectionTrafficSecrets::Aes256Gcm { .. }) => {}
            _ => panic!("expected Aes256Gcm variant"),
        }
        match Tls13ChaCha20Poly1305.extract_keys(AeadKey::from([0u8; 32]), Iv::from([0u8; 12])) {
            Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { .. }) => {}
            _ => panic!("expected Chacha20Poly1305 variant"),
        }
    }
}
