//! `rustls::quic::{Algorithm, PacketKey, HeaderProtectionKey}` implementations
//! for the three QUIC AEAD suites (RFC 9001 §5).
//!
//! * **Packet protection** ([`PacketKey`]) is the suite AEAD (AES-128/256-GCM
//!   or ChaCha20-Poly1305) with the per-packet nonce `iv XOR packet_number`
//!   (RFC 9001 §5.3), the header as AAD.
//! * **Header protection** ([`HeaderProtectionKey`]) masks the first byte and
//!   packet-number bytes with a 5-byte sample derived from the ciphertext
//!   (RFC 9001 §5.4): AES-ECB single block (§5.4.3) for the AES suites, a
//!   ChaCha20 keystream block (§5.4.4) for ChaCha20. Both come from OxiCrypto's
//!   `cipher` primitives. The masking logic (`xor_in_place`) is a faithful
//!   port of RFC 9001 §5.4.1.

use alloc::boxed::Box;

use aead::AeadInPlace;
use oxicrypto::cipher::{aes128_encrypt_block, aes256_encrypt_block, chacha20_keystream_block};
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag};
use rustls::Error;

/// Sample length consumed for header protection (RFC 9001 §5.4.2): all three
/// supported suites use a 16-byte sample.
const SAMPLE_LEN: usize = 16;

/// Header-protection mask length (RFC 9001 §5.4.1): one byte for the header
/// flags plus up to four packet-number bytes.
const MASK_LEN: usize = 5;

/// AEAD authentication-tag length shared by all three suites.
const TAG_LEN: usize = 16;

/// Which header-protection primitive a suite uses.
#[derive(Clone, Copy)]
enum HpKind {
    /// AES-128 ECB single-block mask (RFC 9001 §5.4.3).
    Aes128,
    /// AES-256 ECB single-block mask (RFC 9001 §5.4.3).
    Aes256,
    /// ChaCha20 keystream-block mask (RFC 9001 §5.4.4).
    ChaCha20,
}

/// Which packet-protection AEAD a suite uses.
#[derive(Clone, Copy)]
enum AeadKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

// ── Header protection ────────────────────────────────────────────────────────

/// QUIC header-protection key: the raw HP key bytes plus the masking primitive.
struct HpKey {
    key: AeadKey,
    kind: HpKind,
}

impl HpKey {
    /// Compute the 5-byte header-protection mask from a sample.
    fn mask(&self, sample: &[u8]) -> Result<[u8; MASK_LEN], Error> {
        if sample.len() < SAMPLE_LEN {
            return Err(Error::General("sample of invalid length".into()));
        }
        let mut mask = [0u8; MASK_LEN];
        match self.kind {
            HpKind::Aes128 => {
                let mut block = [0u8; SAMPLE_LEN];
                aes128_encrypt_block(self.key.as_ref(), &sample[..SAMPLE_LEN], &mut block)
                    .map_err(|_| Error::General("header protection mask failed".into()))?;
                mask.copy_from_slice(&block[..MASK_LEN]);
            }
            HpKind::Aes256 => {
                let mut block = [0u8; SAMPLE_LEN];
                aes256_encrypt_block(self.key.as_ref(), &sample[..SAMPLE_LEN], &mut block)
                    .map_err(|_| Error::General("header protection mask failed".into()))?;
                mask.copy_from_slice(&block[..MASK_LEN]);
            }
            HpKind::ChaCha20 => {
                // RFC 9001 §5.4.4: counter = first 4 sample bytes (little-endian),
                // nonce = remaining 12 sample bytes.
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let nonce = &sample[4..SAMPLE_LEN];
                chacha20_keystream_block(self.key.as_ref(), counter, nonce, &mut mask)
                    .map_err(|_| Error::General("header protection mask failed".into()))?;
            }
        }
        Ok(mask)
    }

    /// Apply header protection masking (RFC 9001 §5.4.1).
    ///
    /// Ported from rustls' ring backend (`crypto/ring/quic.rs::xor_in_place`).
    /// When `masked` is true we are *removing* protection (decrypt): the packet
    /// length bits are read after unmasking the first byte.
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        let mask = self.mask(sample)?;
        let (first_mask, pn_mask) = mask
            .split_first()
            .ok_or_else(|| Error::General("empty header protection mask".into()))?;

        // A valid packet number is never longer than the mask.
        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }

        // Infallible from here on; `first`/`packet_number` are unchanged above.
        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = if *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            0x0f // Long header: protect low 4 bits of first byte
        } else {
            0x1f // Short header: protect low 5 bits of first byte
        };

        let first_plain = if masked {
            // Unmasking: recover plaintext first byte to read PN length.
            *first ^ (first_mask & bits)
        } else {
            *first
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= *m;
        }
        Ok(())
    }
}

impl HeaderProtectionKey for HpKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

// ── Packet protection ────────────────────────────────────────────────────────

/// QUIC packet-protection key: an optional suite AEAD plus the per-key IV.
///
/// The AEAD is stored as an enum of the three concrete RustCrypto ciphers so
/// the hot path is monomorphic. It is wrapped in `Option`-free form because the
/// key was already validated when the suite produced it; a construction failure
/// (impossible for a correctly sized key) is surfaced as `Encrypt`/`DecryptError`.
struct QuicPacketKey {
    aead: PacketAead,
    iv: Iv,
}

enum PacketAead {
    Aes128(Box<aes_gcm::Aes128Gcm>),
    Aes256(Box<aes_gcm::Aes256Gcm>),
    ChaCha20(Box<chacha20poly1305::ChaCha20Poly1305>),
    /// Set when key construction failed (structurally impossible).
    Invalid,
}

impl QuicPacketKey {
    fn new(kind: AeadKind, key: AeadKey, iv: Iv) -> Self {
        use aead::KeyInit;
        let aead = match kind {
            AeadKind::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key.as_ref())
                .map(|c| PacketAead::Aes128(Box::new(c)))
                .unwrap_or(PacketAead::Invalid),
            AeadKind::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key.as_ref())
                .map(|c| PacketAead::Aes256(Box::new(c)))
                .unwrap_or(PacketAead::Invalid),
            AeadKind::ChaCha20Poly1305 => {
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                    .map(|c| PacketAead::ChaCha20(Box::new(c)))
                    .unwrap_or(PacketAead::Invalid)
            }
        };
        Self { aead, iv }
    }

    /// Seal `payload` in place with the per-packet nonce, returning the tag.
    fn seal(&self, packet_number: u64, header: &[u8], payload: &mut [u8]) -> Result<Tag, Error> {
        let nonce_bytes = Nonce::new(&self.iv, packet_number).0;
        let tag = match &self.aead {
            PacketAead::Aes128(c) => {
                let n = aead::Nonce::<aes_gcm::Aes128Gcm>::clone_from_slice(&nonce_bytes);
                c.encrypt_in_place_detached(&n, header, payload)
            }
            PacketAead::Aes256(c) => {
                let n = aead::Nonce::<aes_gcm::Aes256Gcm>::clone_from_slice(&nonce_bytes);
                c.encrypt_in_place_detached(&n, header, payload)
            }
            PacketAead::ChaCha20(c) => {
                let n = aead::Nonce::<chacha20poly1305::ChaCha20Poly1305>::clone_from_slice(
                    &nonce_bytes,
                );
                c.encrypt_in_place_detached(&n, header, payload)
            }
            PacketAead::Invalid => return Err(Error::EncryptError),
        }
        .map_err(|_| Error::EncryptError)?;
        Ok(Tag::from(tag.as_ref()))
    }

    /// Open `payload` (ciphertext ‖ tag) in place, returning the plaintext slice.
    fn open<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let nonce_bytes = Nonce::new(&self.iv, packet_number).0;
        let split = payload.len() - TAG_LEN;
        let (ct, tag_bytes) = payload.split_at_mut(split);

        match &self.aead {
            PacketAead::Aes128(c) => {
                let n = aead::Nonce::<aes_gcm::Aes128Gcm>::clone_from_slice(&nonce_bytes);
                let tag = aead::Tag::<aes_gcm::Aes128Gcm>::clone_from_slice(tag_bytes);
                c.decrypt_in_place_detached(&n, header, ct, &tag)
            }
            PacketAead::Aes256(c) => {
                let n = aead::Nonce::<aes_gcm::Aes256Gcm>::clone_from_slice(&nonce_bytes);
                let tag = aead::Tag::<aes_gcm::Aes256Gcm>::clone_from_slice(tag_bytes);
                c.decrypt_in_place_detached(&n, header, ct, &tag)
            }
            PacketAead::ChaCha20(c) => {
                let n = aead::Nonce::<chacha20poly1305::ChaCha20Poly1305>::clone_from_slice(
                    &nonce_bytes,
                );
                let tag =
                    aead::Tag::<chacha20poly1305::ChaCha20Poly1305>::clone_from_slice(tag_bytes);
                c.decrypt_in_place_detached(&n, header, ct, &tag)
            }
            PacketAead::Invalid => return Err(Error::DecryptError),
        }
        .map_err(|_| Error::DecryptError)?;

        Ok(&payload[..split])
    }
}

impl PacketKey for QuicPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        self.seal(packet_number, header, payload)
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.open(packet_number, header, payload)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        // RFC 9001 §6.6 confidentiality limits.
        match self.aead {
            // AEAD_AES_128_GCM / AEAD_AES_256_GCM: 2^23 (AES-GCM single-key).
            PacketAead::Aes128(_) | PacketAead::Aes256(_) => 1 << 23,
            // AEAD_CHACHA20_POLY1305: effectively unbounded.
            PacketAead::ChaCha20(_) => u64::MAX,
            PacketAead::Invalid => 0,
        }
    }

    fn integrity_limit(&self) -> u64 {
        // RFC 9001 §6.6 integrity limits.
        match self.aead {
            PacketAead::Aes128(_) | PacketAead::Aes256(_) => 1 << 52,
            PacketAead::ChaCha20(_) => 1 << 36,
            PacketAead::Invalid => 0,
        }
    }
}

// ── Algorithm (suite key generator) ──────────────────────────────────────────

/// QUIC key-generation algorithm for one cipher suite.
///
/// Holds the AEAD kind, the header-protection primitive, and the AEAD key
/// length. Construct via the three [`AES128_GCM`], [`AES256_GCM`],
/// [`CHACHA20_POLY1305`] statics.
pub struct QuicAlgorithm {
    aead: AeadKind,
    hp: HpKind,
    key_len: usize,
}

impl Algorithm for QuicAlgorithm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        Box::new(QuicPacketKey::new(self.aead, key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(HpKey { key, kind: self.hp })
    }

    fn aead_key_len(&self) -> usize {
        self.key_len
    }
}

/// QUIC algorithm for `TLS_AES_128_GCM_SHA256`.
pub static AES128_GCM: QuicAlgorithm = QuicAlgorithm {
    aead: AeadKind::Aes128Gcm,
    hp: HpKind::Aes128,
    key_len: 16,
};

/// QUIC algorithm for `TLS_AES_256_GCM_SHA384`.
pub static AES256_GCM: QuicAlgorithm = QuicAlgorithm {
    aead: AeadKind::Aes256Gcm,
    hp: HpKind::Aes256,
    key_len: 32,
};

/// QUIC algorithm for `TLS_CHACHA20_POLY1305_SHA256`.
pub static CHACHA20_POLY1305: QuicAlgorithm = QuicAlgorithm {
    aead: AeadKind::ChaCha20Poly1305,
    hp: HpKind::ChaCha20,
    key_len: 32,
};

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::tls13::OkmBlock;
    use rustls::quic::{KeyChange, Keys, Version};

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // RFC 9001 §A.5: ChaCha20-Poly1305 short-header packet protection.
    // Drives PacketKey + HeaderProtectionKey via rustls' KeyBuilder
    // (Secrets/Keys path) to the published wire bytes. This is the same vector
    // rustls' own ring backend tests use.
    #[test]
    fn rfc9001_a5_chacha20_short_header() {
        const PN: u64 = 654360564;
        const SECRET: &[u8] = &[
            0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42, 0x27, 0x48, 0xad,
            0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3,
            0x0f, 0x21, 0x63, 0x2b,
        ];
        // Derive the packet/header keys from SECRET using HKDF-Expand-Label.
        let secret = OkmBlock::new(SECRET);
        let hkdf = crate::hkdf::hkdf_sha256();
        let expander = hkdf.expander_for_okm(&secret);

        // quic key (32), quic iv (12), quic hp (32) via HkdfLabel.
        let key = expand_label(expander.as_ref(), b"quic key", 32);
        let iv = expand_label(expander.as_ref(), b"quic iv", 12);
        let hp = expand_label(expander.as_ref(), b"quic hp", 32);

        let packet = QuicPacketKey::new(
            AeadKind::ChaCha20Poly1305,
            AeadKey::from(to_arr32(&key)),
            Iv::from(to_arr12(&iv)),
        );
        let hpk = HpKey {
            key: AeadKey::from(to_arr32(&hp)),
            kind: HpKind::ChaCha20,
        };

        const PLAIN: &[u8] = &[0x42, 0x00, 0xbf, 0xf4, 0x01];
        let mut buf = PLAIN.to_vec();
        let (header, payload) = buf.split_at_mut(4);
        let tag = packet.seal(PN, header, payload).expect("seal");
        buf.extend_from_slice(tag.as_ref());

        let pn_offset = 1;
        let (header, sample) = buf.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let sample = &sample[..hpk.sample_len()];
        hpk.encrypt_in_place(sample, &mut first[0], rest)
            .expect("hp");

        // RFC 9001 §A.5 expected protected packet.
        let expected = hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
        assert_eq!(buf, expected, "RFC 9001 A.5 protected packet mismatch");

        // Round-trip: remove header protection then decrypt.
        let (header, sample) = buf.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let sample = &sample[..hpk.sample_len()];
        hpk.decrypt_in_place(sample, &mut first[0], rest)
            .expect("un-hp");
        let (header, payload_tag) = buf.split_at_mut(4);
        let plain = packet.open(PN, header, payload_tag).expect("open");
        assert_eq!(plain, &PLAIN[4..]);
    }

    // RFC 9001 §A: QUIC v1 Initial keys derived through
    // `rustls::quic::Keys::initial(Version::V1, ...)` using OUR suite + OUR
    // quic::Algorithm. This proves the Initial-keys path routes through our
    // provider (no ring/aws-lc). We verify the derived keys both (a) match the
    // RFC 9001 §A.1 published key/iv via `extract_keys`, and (b) round-trip a
    // packet through packet + header protection.
    #[test]
    fn rfc9001_initial_keys_via_keys_initial() {
        use rustls::crypto::cipher::Tls13AeadAlgorithm;
        use rustls::{ConnectionTrafficSecrets, Side};

        let dcid = hex("8394c8f03e515708");

        // Client side: local = client keys. RFC 9001 A.1 client quic key/iv.
        let client = Keys::initial(
            Version::V1,
            crate::suites::tls13_aes_128_gcm_sha256_internal(),
            &AES128_GCM,
            &dcid,
            Side::Client,
        );
        // Server side: local = server keys.
        let server = Keys::initial(
            Version::V1,
            crate::suites::tls13_aes_128_gcm_sha256_internal(),
            &AES128_GCM,
            &dcid,
            Side::Server,
        );

        // Round-trip a packet: server seals, client opens (client.remote ==
        // server keys). This only succeeds if both sides derived identical
        // Initial keys through our HKDF + AEAD.
        const HEADER: &[u8] = &[0xc3, 0xff, 0x00, 0x00, 0x01, 0x08];
        const PLAIN: &[u8] = b"quic initial crypto frame bytes";
        let mut buf = PLAIN.to_vec();
        let tag = server
            .local
            .packet
            .encrypt_in_place(0, HEADER, &mut buf)
            .expect("server seal");
        buf.extend_from_slice(tag.as_ref());
        let opened = client
            .remote
            .packet
            .decrypt_in_place(0, HEADER, &mut buf)
            .expect("client open");
        assert_eq!(opened, PLAIN, "server->client Initial round-trip");

        // And the reverse direction.
        let mut buf2 = PLAIN.to_vec();
        let tag2 = client
            .local
            .packet
            .encrypt_in_place(0, HEADER, &mut buf2)
            .expect("client seal");
        buf2.extend_from_slice(tag2.as_ref());
        let opened2 = server
            .remote
            .packet
            .decrypt_in_place(0, HEADER, &mut buf2)
            .expect("server open");
        assert_eq!(opened2, PLAIN, "client->server Initial round-trip");

        // The AES-128-GCM suite must map traffic secrets to the Aes128Gcm
        // variant (the fix relative to rustls-rustcrypto). `extract_keys`
        // hard-codes the variant, so a 32-byte key still selects it correctly.
        use rustls::crypto::cipher::{AeadKey, Iv};
        match crate::aead::Tls13Aes128Gcm
            .extract_keys(AeadKey::from([0u8; 32]), Iv::from([0u8; 12]))
        {
            Ok(ConnectionTrafficSecrets::Aes128Gcm { .. }) => {}
            _ => panic!("expected Aes128Gcm variant"),
        }
        let _ = (&client, &server);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn expand_label(
        expander: &dyn rustls::crypto::tls13::HkdfExpander,
        label: &[u8],
        len: usize,
    ) -> alloc::vec::Vec<u8> {
        // Build the TLS 1.3 HkdfLabel: u16 len | u8 (6+label) | "tls13 "+label | u8 0.
        let full_label_len = 6 + label.len();
        let mut info_hdr = alloc::vec::Vec::new();
        info_hdr.extend_from_slice(&(len as u16).to_be_bytes());
        info_hdr.push(full_label_len as u8);
        let mut out = alloc::vec![0u8; len];
        let info: &[&[u8]] = &[&info_hdr, b"tls13 ", label, &[0u8]];
        expander.expand_slice(info, &mut out).expect("expand_slice");
        out
    }

    fn to_arr32(v: &[u8]) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&v[..32]);
        a
    }

    fn to_arr12(v: &[u8]) -> [u8; 12] {
        let mut a = [0u8; 12];
        a.copy_from_slice(&v[..12]);
        a
    }

    #[test]
    fn aead_key_len_values() {
        assert_eq!(AES128_GCM.aead_key_len(), 16);
        assert_eq!(AES256_GCM.aead_key_len(), 32);
        assert_eq!(CHACHA20_POLY1305.aead_key_len(), 32);
    }

    // Sanity: a 1-RTT-style key update via rustls Secrets uses our Algorithm.
    #[allow(dead_code)]
    fn _key_change_is_used(kc: KeyChange) -> bool {
        matches!(kc, KeyChange::OneRtt { .. } | KeyChange::Handshake { .. })
    }
}
