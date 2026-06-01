//! QUIC packet coding and protection (RFC 9000 Section 17, RFC 9001 Sections
//! 5.3–5.4).
//!
//! This module assembles and disassembles protected QUIC packets:
//!
//! * Long-header (Initial/Handshake) and short-header (1-RTT) packet builders
//!   that write the cleartext header, seal the payload with a
//!   [`rustls::quic::PacketKey`] (AEAD over the header as AAD), then apply header
//!   protection ([`rustls::quic::HeaderProtectionKey`]).
//! * A receive-side parser that locates each packet within a (possibly
//!   coalesced) datagram, removes header protection, recovers the packet number
//!   and decrypts the payload.
//!
//! Header protection is applied *after* payload encryption on send and removed
//! *before* payload decryption on receive, using a 16-byte sample taken at a
//! fixed offset of four bytes past the start of the packet-number field
//! (RFC 9001 Section 5.4.2).

use crate::coding::{
    decode_packet_number, encode_packet_number, packet_number_len, put_varint, Buf, CodecError,
};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use oxiquic_core::PacketType;
use rustls::quic::{HeaderProtectionKey, PacketKey};

/// The HP sample length and offset constants from RFC 9001 Section 5.4.2: the
/// sample is taken four bytes after the start of the packet number, which is
/// the longest a packet number may be.
const HP_SAMPLE_OFFSET: usize = 4;

/// An error encountered building or parsing a protected packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// The datagram was truncated relative to its declared lengths.
    Truncated,
    /// A header field was malformed (bad CID length, reserved bits, etc.); the
    /// payload names the offending field.
    Malformed(&'static str),
    /// Header-protection removal or AEAD decryption failed.
    Crypto,
    /// The long-header packet carried a QUIC version this endpoint does not
    /// speak; the payload is the wire version value.
    Version(u32),
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated packet"),
            Self::Malformed(field) => write!(f, "malformed packet: {field}"),
            Self::Crypto => f.write_str("packet protection failed"),
            Self::Version(v) => write!(f, "unsupported QUIC version 0x{v:08x}"),
        }
    }
}

impl From<CodecError> for PacketError {
    fn from(_: CodecError) -> Self {
        Self::Truncated
    }
}

/// Which long-header packet type a builder emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongType {
    /// Initial packet (carries a Token field).
    Initial,
    /// 0-RTT packet (RFC 9000 §17.2.3): type bits `0b01`.
    /// Does NOT carry a Token field; shares the Application packet-number space.
    ZeroRtt,
    /// Handshake packet.
    Handshake,
}

impl LongType {
    const fn type_bits(self) -> u8 {
        match self {
            // QUIC v1 long packet type bits (RFC 9000 Section 17.2).
            LongType::Initial => 0b00,
            LongType::ZeroRtt => 0b01,
            LongType::Handshake => 0b10,
        }
    }
}

/// Parameters describing where to encrypt a packet and what header to write.
pub struct BuildLong<'a> {
    /// Initial vs Handshake.
    pub long_type: LongType,
    /// QUIC version (wire value).
    pub version: u32,
    /// Destination connection ID (the peer's CID).
    pub dcid: &'a [u8],
    /// Source connection ID (our CID).
    pub scid: &'a [u8],
    /// Token bytes for an Initial packet (empty for Handshake / client first
    /// flight without a token).
    pub token: &'a [u8],
    /// Full packet number for this packet.
    pub packet_number: u64,
    /// Largest packet number acknowledged in this space, for PN truncation.
    pub largest_acked: Option<u64>,
}

/// Build and protect a long-header packet, appending it to `datagram`.
///
/// `payload` holds the cleartext frame bytes; it is consumed (encrypted in
/// place internally via a scratch copy). Returns the number of bytes appended.
///
/// # Errors
/// Returns [`PacketError::Crypto`] if AEAD sealing or header protection fails.
pub fn build_long_packet(
    datagram: &mut Vec<u8>,
    params: &BuildLong<'_>,
    payload: &[u8],
    packet_key: &dyn PacketKey,
    header_key: &dyn HeaderProtectionKey,
) -> Result<usize, PacketError> {
    let start = datagram.len();
    let pn_len = packet_number_len(params.packet_number, params.largest_acked);

    // First byte: 1 (long) 1 (fixed) TT (type) 00 (reserved) PP (pn_len-1).
    let first = 0x80 | 0x40 | (params.long_type.type_bits() << 4) | ((pn_len as u8) - 1);
    datagram.push(first);
    datagram.extend_from_slice(&params.version.to_be_bytes());
    datagram.push(params.dcid.len() as u8);
    datagram.extend_from_slice(params.dcid);
    datagram.push(params.scid.len() as u8);
    datagram.extend_from_slice(params.scid);
    if params.long_type == LongType::Initial {
        put_varint(datagram, params.token.len() as u64);
        datagram.extend_from_slice(params.token);
    }

    // Length field covers the packet number plus the encrypted payload+tag.
    let tag_len = packet_key.tag_len();
    let length = pn_len + payload.len() + tag_len;
    put_varint(datagram, length as u64);

    let pn_offset = datagram.len();
    encode_packet_number(datagram, params.packet_number, pn_len);

    let layout = PnLayout {
        start,
        pn_offset,
        pn_len,
        packet_number: params.packet_number,
    };
    finish_packet(datagram, &layout, payload, packet_key, header_key)?;
    Ok(datagram.len() - start)
}

/// Parameters for building a short-header (1-RTT) packet.
pub struct BuildShort<'a> {
    /// Destination connection ID (the peer's CID).
    pub dcid: &'a [u8],
    /// Full packet number for this packet.
    pub packet_number: u64,
    /// Largest packet number acknowledged in this space, for PN truncation.
    pub largest_acked: Option<u64>,
    /// Key Phase bit (RFC 9001 §6): `false` = Key Phase 0, `true` = Key Phase 1.
    pub key_phase: bool,
}

/// Build and protect a short-header (1-RTT) packet, appending it to `datagram`.
///
/// `key_phase` sets bit 0x04 of the first byte (RFC 9001 §6): `false` means
/// Key Phase 0, `true` means Key Phase 1.  Both endpoints must use the same
/// phase value after a key update.
///
/// # Errors
/// Returns [`PacketError::Crypto`] on seal/HP failure.
pub fn build_short_packet(
    datagram: &mut Vec<u8>,
    params: &BuildShort<'_>,
    payload: &[u8],
    packet_key: &dyn PacketKey,
    header_key: &dyn HeaderProtectionKey,
) -> Result<usize, PacketError> {
    let dcid = params.dcid;
    let packet_number = params.packet_number;
    let largest_acked = params.largest_acked;
    let key_phase = params.key_phase;
    let start = datagram.len();
    let pn_len = packet_number_len(packet_number, largest_acked);

    // First byte: 0 (short) 1 (fixed) 0 (spin) 00 (reserved) K (key phase) PP.
    // Bit 0x04 is the Key Phase bit (RFC 9001 §6).
    let key_phase_bit = if key_phase { 0x04 } else { 0x00 };
    let first = 0x40 | key_phase_bit | ((pn_len as u8) - 1);
    datagram.push(first);
    datagram.extend_from_slice(dcid);

    let pn_offset = datagram.len();
    encode_packet_number(datagram, packet_number, pn_len);

    let layout = PnLayout {
        start,
        pn_offset,
        pn_len,
        packet_number,
    };
    finish_packet(datagram, &layout, payload, packet_key, header_key)?;
    Ok(datagram.len() - start)
}

/// Packet-number layout within the datagram, used by [`finish_packet`].
struct PnLayout {
    /// Byte offset of the start of the packet (before the first-byte header).
    start: usize,
    /// Byte offset of the packet-number field.
    pn_offset: usize,
    /// Encoded length of the packet-number field (1–4 bytes).
    pn_len: usize,
    /// Full packet number (pre-truncation value used for AEAD nonce).
    packet_number: u64,
}

/// Seal the payload and apply header protection, shared by long/short builders.
fn finish_packet(
    datagram: &mut Vec<u8>,
    layout: &PnLayout,
    payload: &[u8],
    packet_key: &dyn PacketKey,
    header_key: &dyn HeaderProtectionKey,
) -> Result<(), PacketError> {
    let start = layout.start;
    let pn_offset = layout.pn_offset;
    let pn_len = layout.pn_len;
    let packet_number = layout.packet_number;
    // RFC 9001 §5.4.2: the HP sample is taken 4 bytes past the start of the PN
    // field.  The sample window must fit entirely within the ciphertext+tag.
    // ciphertext_end = pn_offset + pn_len + plaintext_len + tag_len
    // sample_end     = pn_offset + HP_SAMPLE_OFFSET + sample_len
    // Require: pn_offset + HP_SAMPLE_OFFSET + sample_len
    //        <= pn_offset + pn_len + plaintext_len + tag_len
    //  → plaintext_len >= HP_SAMPLE_OFFSET + sample_len - pn_len - tag_len
    //
    // With HP_SAMPLE_OFFSET=4, sample_len=16, tag_len=16: min = 4 - pn_len.
    // For pn_len=1: min plaintext = 3; pn_len>=4: min = 0 (always satisfied).
    // PADDING frames (0x00) are appended to the plaintext to reach the minimum.
    let sample_len = header_key.sample_len();
    let tag_len = 16usize; // AEAD_AES_128_GCM and AEAD_CHACHA20_POLY1305 tags are 16 bytes
    let min_plaintext = (HP_SAMPLE_OFFSET + sample_len).saturating_sub(pn_len + tag_len);
    let mut padded_payload;
    let effective_payload = if payload.len() < min_plaintext {
        padded_payload = payload.to_vec();
        padded_payload.resize(min_plaintext, 0x00); // 0x00 = PADDING frame
        &padded_payload[..]
    } else {
        payload
    };

    // The cleartext header is everything written so far in this packet; it is
    // the AAD for the AEAD seal.
    let header = datagram[start..].to_vec();
    let mut sealed = effective_payload.to_vec();
    let tag = packet_key
        .encrypt_in_place(packet_number, &header, &mut sealed)
        .map_err(|_| PacketError::Crypto)?;
    datagram.extend_from_slice(&sealed);
    datagram.extend_from_slice(tag.as_ref());

    // Apply header protection: sample is 16 bytes starting four bytes past the
    // start of the packet number field.
    let sample_start = pn_offset + HP_SAMPLE_OFFSET;
    let sample_len = header_key.sample_len();
    let sample = datagram
        .get(sample_start..sample_start + sample_len)
        .ok_or(PacketError::Crypto)?
        .to_vec();
    // Split so we can mutate the first byte and the PN bytes independently.
    let (first_byte, pn_bytes) = {
        let (head, rest) = datagram.split_at_mut(start + 1);
        let first = &mut head[start];
        let pn = &mut rest[pn_offset - start - 1..pn_offset - start - 1 + pn_len];
        (first, pn)
    };
    header_key
        .encrypt_in_place(&sample, first_byte, pn_bytes)
        .map_err(|_| PacketError::Crypto)?;
    Ok(())
}

/// A parsed, decrypted packet borrowed from the receive buffer.
pub struct ParsedPacket {
    /// The packet's classification.
    pub packet_type: PacketType,
    /// Source connection ID (long header only; empty for short header).
    pub scid: Vec<u8>,
    /// Destination connection ID.
    pub dcid: Vec<u8>,
    /// The recovered full packet number.
    pub packet_number: u64,
    /// The decrypted frame payload.
    pub payload: Vec<u8>,
    /// Total bytes this packet occupied in the datagram (for coalescing).
    pub consumed: usize,
    /// Key Phase bit from the short header after header-protection removal
    /// (RFC 9001 §6: bit 0x04 of the first byte). Always `false` for
    /// long-header packets.
    pub key_phase: bool,
}

/// Long-header fields located before header-protection removal.
struct LongHeaderLayout {
    packet_type: PacketType,
    version: u32,
    scid: Vec<u8>,
    dcid: Vec<u8>,
    /// Absolute offset of the packet number within the datagram.
    pn_offset: usize,
    /// Absolute end offset of this packet's bytes within the datagram.
    packet_end: usize,
}

/// Parse the invariant + version-specific fields of a long header beginning at
/// `offset` within `datagram`, returning absolute offsets for the packet number
/// and packet end.
fn parse_long_header(
    datagram: &[u8],
    offset: usize,
    first: u8,
) -> Result<LongHeaderLayout, PacketError> {
    let mut buf = Buf::new(&datagram[offset..]);
    let _ = buf.get_u8()?; // first byte
    let version = buf.get_u32()?;
    let dcid_len = buf.get_u8()? as usize;
    if dcid_len > 20 {
        return Err(PacketError::Malformed("dcid too long"));
    }
    let dcid = buf.get_bytes(dcid_len)?.to_vec();
    let scid_len = buf.get_u8()? as usize;
    if scid_len > 20 {
        return Err(PacketError::Malformed("scid too long"));
    }
    let scid = buf.get_bytes(scid_len)?.to_vec();

    let packet_type = PacketType::from_first_byte_and_version(first, version);
    if packet_type == PacketType::Initial {
        let token_len = buf.get_varint()? as usize;
        let _ = buf.get_bytes(token_len)?;
    }
    // All of Initial/Handshake/0-RTT carry a Length field.
    let length = buf.get_varint()? as usize;
    let pn_offset = offset + buf.position();
    let packet_end = pn_offset
        .checked_add(length)
        .ok_or(PacketError::Truncated)?;
    if packet_end > datagram.len() {
        return Err(PacketError::Truncated);
    }
    Ok(LongHeaderLayout {
        packet_type,
        version,
        scid,
        dcid,
        pn_offset,
        packet_end,
    })
}

/// Remove header protection and decrypt one long-header packet beginning at
/// `offset` within `datagram` (supports coalesced datagrams).
///
/// `largest_pn` is the largest packet number already processed in this space
/// (for PN recovery). [`ParsedPacket::consumed`] is the absolute end offset of
/// this packet, i.e. where the next coalesced packet begins.
///
/// # Errors
/// Returns [`PacketError`] for truncation, malformed headers, version
/// mismatch, or crypto failure.
pub fn parse_long_packet(
    datagram: &mut [u8],
    offset: usize,
    expected_version: u32,
    largest_pn: Option<u64>,
    packet_key: &dyn PacketKey,
    header_key: &dyn HeaderProtectionKey,
) -> Result<ParsedPacket, PacketError> {
    let first = *datagram.get(offset).ok_or(PacketError::Truncated)?;
    let layout = parse_long_header(datagram, offset, first)?;
    if layout.version != expected_version {
        return Err(PacketError::Version(layout.version));
    }
    let (packet_number, payload, _first) = unprotect_and_decrypt(
        datagram,
        offset,
        layout.pn_offset,
        layout.packet_end,
        largest_pn,
        packet_key,
        header_key,
    )?;
    Ok(ParsedPacket {
        packet_type: layout.packet_type,
        scid: layout.scid,
        dcid: layout.dcid,
        packet_number,
        payload,
        consumed: layout.packet_end,
        key_phase: false, // long headers do not carry a Key Phase bit
    })
}

/// Remove header protection and decrypt a short-header (1-RTT) packet, which
/// occupies the entire datagram from `offset` to the end.
///
/// `dcid_len` is the length of our locally-issued connection ID (short headers
/// carry no CID-length field, so the receiver must know it).
///
/// # Errors
/// Returns [`PacketError`] on truncation or crypto failure.
pub fn parse_short_packet(
    datagram: &mut [u8],
    offset: usize,
    dcid_len: usize,
    largest_pn: Option<u64>,
    packet_key: &dyn PacketKey,
    header_key: &dyn HeaderProtectionKey,
) -> Result<ParsedPacket, PacketError> {
    if offset >= datagram.len() {
        return Err(PacketError::Truncated);
    }
    let dcid = datagram
        .get(offset + 1..offset + 1 + dcid_len)
        .ok_or(PacketError::Truncated)?
        .to_vec();
    let pn_offset = offset + 1 + dcid_len;
    let packet_end = datagram.len();
    let (packet_number, payload, deprotected_first) = unprotect_and_decrypt(
        datagram, offset, pn_offset, packet_end, largest_pn, packet_key, header_key,
    )?;
    // RFC 9001 §6: the key phase bit is bit 0x04 of the first byte of the
    // short header, read from the deprotected value.
    let key_phase = (deprotected_first & 0x04) != 0;
    Ok(ParsedPacket {
        packet_type: PacketType::Short,
        scid: Vec::new(),
        dcid,
        packet_number,
        payload,
        consumed: packet_end,
        key_phase,
    })
}

/// Remove header protection from a short-header packet and return the
/// deprotected key phase bit without attempting AEAD decryption.
///
/// This is used by the key-update receive path (RFC 9001 §6): the caller
/// strips HP with the *current* header protection key (which never changes
/// during a key update), reads the key phase bit to select the right packet
/// key, and then calls [`parse_short_packet`] (or a re-entry variant) with
/// the chosen key.
///
/// After this call the datagram bytes at `offset` have been modified
/// in-place (HP removed).  `datagram` must NOT be re-protected; pass the
/// modified slice directly to the AEAD-decrypt step.
///
/// Returns `(key_phase, deprotected_first_byte)`, or [`PacketError`] on
/// truncation or HP failure.
///
/// # Errors
/// Returns [`PacketError`] on truncation or header-protection failure.
pub fn strip_short_header_protection(
    datagram: &mut [u8],
    offset: usize,
    dcid_len: usize,
    header_key: &dyn HeaderProtectionKey,
) -> Result<(bool, u8), PacketError> {
    if offset >= datagram.len() {
        return Err(PacketError::Truncated);
    }
    let pn_offset = offset + 1 + dcid_len;
    let packet_end = datagram.len();
    let sample_start = pn_offset + HP_SAMPLE_OFFSET;
    let sample_len = header_key.sample_len();
    if sample_start + sample_len > packet_end {
        return Err(PacketError::Truncated);
    }
    let sample = datagram[sample_start..sample_start + sample_len].to_vec();

    let (head, pn_tail) = datagram.split_at_mut(pn_offset);
    let first_byte = head
        .get_mut(offset)
        .ok_or(PacketError::Malformed("missing first byte"))?;
    let pn_field_len = pn_tail.len().min(4);
    let pn_field = pn_tail
        .get_mut(..pn_field_len)
        .ok_or(PacketError::Truncated)?;
    header_key
        .decrypt_in_place(&sample, first_byte, pn_field)
        .map_err(|_| PacketError::Crypto)?;

    let deprotected_first = *first_byte;
    let key_phase = (deprotected_first & 0x04) != 0;
    Ok((key_phase, deprotected_first))
}

/// Decrypt a short-header packet whose header protection has already been
/// stripped by [`strip_short_header_protection`].
///
/// This is the second half of the key-update receive path, called after the
/// caller has selected the appropriate packet key based on the key phase bit.
///
/// # Errors
/// Returns [`PacketError`] on truncation or AEAD failure.
pub fn decrypt_short_packet_body(
    datagram: &mut [u8],
    offset: usize,
    dcid_len: usize,
    largest_pn: Option<u64>,
    packet_key: &dyn PacketKey,
) -> Result<ParsedPacket, PacketError> {
    if offset >= datagram.len() {
        return Err(PacketError::Truncated);
    }
    let dcid = datagram
        .get(offset + 1..offset + 1 + dcid_len)
        .ok_or(PacketError::Truncated)?
        .to_vec();
    let pn_offset = offset + 1 + dcid_len;
    let packet_end = datagram.len();

    // Header protection already removed; read deprotected first byte directly.
    let deprotected_first = datagram[offset];
    let key_phase = (deprotected_first & 0x04) != 0;
    let pn_len = ((deprotected_first & 0x03) + 1) as usize;
    if pn_offset + pn_len > packet_end {
        return Err(PacketError::Truncated);
    }
    let mut truncated = 0u64;
    for &b in &datagram[pn_offset..pn_offset + pn_len] {
        truncated = (truncated << 8) | u64::from(b);
    }
    let packet_number = decode_packet_number(largest_pn, truncated, pn_len);

    let header = datagram[offset..pn_offset + pn_len].to_vec();
    let payload_start = pn_offset + pn_len;
    if payload_start > packet_end {
        return Err(PacketError::Truncated);
    }
    let payload = datagram
        .get_mut(payload_start..packet_end)
        .ok_or(PacketError::Truncated)?;
    let plaintext = packet_key
        .decrypt_in_place(packet_number, &header, payload)
        .map_err(|_| PacketError::Crypto)?;
    Ok(ParsedPacket {
        packet_type: PacketType::Short,
        scid: Vec::new(),
        dcid,
        packet_number,
        payload: plaintext.to_vec(),
        consumed: packet_end,
        key_phase,
    })
}

/// Shared HP-removal + AEAD-open over a packet that begins at `packet_start`,
/// has its packet number located at `pn_offset` and ends at `packet_end` (all
/// offsets are into `datagram`). Returns `(packet_number, plaintext,
/// deprotected_first_byte)`.
fn unprotect_and_decrypt(
    datagram: &mut [u8],
    packet_start: usize,
    pn_offset: usize,
    packet_end: usize,
    largest_pn: Option<u64>,
    packet_key: &dyn PacketKey,
    header_key: &dyn HeaderProtectionKey,
) -> Result<(u64, Vec<u8>, u8), PacketError> {
    let sample_start = pn_offset + HP_SAMPLE_OFFSET;
    let sample_len = header_key.sample_len();
    if sample_start + sample_len > packet_end {
        return Err(PacketError::Truncated);
    }
    let sample = datagram[sample_start..sample_start + sample_len].to_vec();

    // Remove header protection. The masked first byte of the packet lives at
    // `packet_start`; the packet number begins at `pn_offset`. HP treats the PN
    // as the maximal four bytes, then we read its true length from the
    // now-cleartext first byte. Split the slice so the first byte and the PN
    // field are disjoint mutable borrows.
    let (head, pn_tail) = datagram.split_at_mut(pn_offset);
    let first_byte = head
        .get_mut(packet_start)
        .ok_or(PacketError::Malformed("missing first byte"))?;
    let pn_field_len = pn_tail.len().min(4);
    let pn_field = pn_tail
        .get_mut(..pn_field_len)
        .ok_or(PacketError::Truncated)?;
    header_key
        .decrypt_in_place(&sample, first_byte, pn_field)
        .map_err(|_| PacketError::Crypto)?;

    // Save the deprotected first byte so callers can read header bits such as
    // the Key Phase bit (0x04) from short headers (RFC 9001 §6).
    let deprotected_first = *first_byte;

    let pn_len = ((deprotected_first & 0x03) + 1) as usize;
    let mut truncated = 0u64;
    for &b in &datagram[pn_offset..pn_offset + pn_len] {
        truncated = (truncated << 8) | u64::from(b);
    }
    let packet_number = decode_packet_number(largest_pn, truncated, pn_len);

    // The header (now deprotected) is the AAD; payload follows the PN.
    let header = datagram[packet_start..pn_offset + pn_len].to_vec();
    let payload_start = pn_offset + pn_len;
    let payload = datagram
        .get_mut(payload_start..packet_end)
        .ok_or(PacketError::Truncated)?;
    let plaintext = packet_key
        .decrypt_in_place(packet_number, &header, payload)
        .map_err(|_| PacketError::Crypto)?;
    Ok((packet_number, plaintext.to_vec(), deprotected_first))
}

// ─── Version Negotiation packet (RFC 9000 Section 17.2.1) ───────────────────
//
// VN packets are UNPROTECTED.  They carry no packet number and use no AEAD;
// the header is trivially the whole datagram.

/// Encode a Version Negotiation packet into a newly-allocated buffer.
///
/// The wire format (RFC 9000 §17.2.1):
/// ```text
///   0b1_0??????     first byte: Header Form=1, Fixed Bit=0, rest arbitrary
///   0x00000000      Version = 0  (distinguishes VN from all other long headers)
///   u8              DCID Len
///   [DCID]          == client's SCID from the triggering Initial
///   u8              SCID Len
///   [SCID]          == client's DCID from the triggering Initial
///   [u32; N]        Supported versions, each big-endian
/// ```
///
/// `client_scid` is echoed as the VN packet's DCID; `client_dcid` is echoed as
/// the VN packet's SCID — so the client can recognise the packet as a response
/// to its own Initial.
#[must_use]
pub fn encode_version_negotiation(
    client_scid: &[u8],
    client_dcid: &[u8],
    supported_versions: &[u32],
) -> Vec<u8> {
    // Capacity: 1 (first) + 4 (version) + 1 (dcid_len) + dcid +
    //           1 (scid_len) + scid + 4*|versions|
    let mut buf = Vec::with_capacity(
        6 + client_scid.len() + client_dcid.len() + 4 * supported_versions.len(),
    );
    // First byte: Header Form (bit 7) = 1; Fixed Bit (bit 6) = 0 (VN marker).
    // Remaining bits are reserved / ignored by receivers.
    buf.push(0x80u8);
    // Version = 0x00000000 — this is the canonical VN identifier.
    buf.extend_from_slice(&0x00_00_00_00u32.to_be_bytes());
    // DCID = client's SCID (so client can match to its own CID).
    buf.push(client_scid.len() as u8);
    buf.extend_from_slice(client_scid);
    // SCID = client's DCID.
    buf.push(client_dcid.len() as u8);
    buf.extend_from_slice(client_dcid);
    // Supported version list.
    for &v in supported_versions {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    buf
}

/// Decode a Version Negotiation packet, returning the list of supported
/// versions carried in its payload.
///
/// Returns `None` if `datagram` is not a well-formed VN packet (wrong header
/// form, non-zero Version field, or truncated CID/version list).
#[must_use]
pub fn decode_version_negotiation(datagram: &[u8]) -> Option<Vec<u32>> {
    let mut buf = Buf::new(datagram);
    let first = buf.get_u8().ok()?;
    // Must have Header Form bit set (long header) and version == 0.
    if first & 0x80 == 0 {
        return None;
    }
    let version = buf.get_u32().ok()?;
    if version != 0 {
        return None;
    }
    // Skip DCID.
    let dcid_len = buf.get_u8().ok()? as usize;
    buf.get_bytes(dcid_len).ok()?;
    // Skip SCID.
    let scid_len = buf.get_u8().ok()? as usize;
    buf.get_bytes(scid_len).ok()?;
    // Remaining bytes are the supported-version list; must be a multiple of 4.
    let remaining = datagram.len() - buf.position();
    if remaining % 4 != 0 {
        return None;
    }
    let mut versions = Vec::with_capacity(remaining / 4);
    for _ in 0..remaining / 4 {
        versions.push(buf.get_u32().ok()?);
    }
    Some(versions)
}

// ─── Retry packet (RFC 9000 §17.2.5, RFC 9001 §5.8) ────────────────────────

/// RFC 9001 §5.8 fixed key for Retry Integrity Tag (AES-128-GCM).
const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// RFC 9001 §5.8 fixed nonce for Retry Integrity Tag.
const RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Compute the 16-byte Retry Integrity Tag (RFC 9001 §5.8).
///
/// The pseudo-packet authenticated is:
/// `[1 byte ODCID length] [ODCID bytes] [retry_packet_without_tag bytes]`
///
/// * `odcid` — the Destination Connection ID from the client's first Initial
/// * `retry_packet_without_tag` — the Retry packet bytes excluding the final 16-byte tag
///
/// Returns `None` only if the AES-128-GCM implementation unexpectedly fails.
#[must_use]
pub fn compute_retry_integrity_tag(
    odcid: &[u8],
    retry_packet_without_tag: &[u8],
) -> Option<[u8; 16]> {
    // Build the pseudo-packet: [odcid_len(1)] [odcid] [retry_without_tag]
    let mut pseudo = Vec::with_capacity(1 + odcid.len() + retry_packet_without_tag.len());
    pseudo.push(odcid.len() as u8);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(retry_packet_without_tag);

    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&RETRY_KEY);
    let cipher = Aes128Gcm::new(key);
    let nonce = aes_gcm::Nonce::from_slice(&RETRY_NONCE);

    // The tag is produced by AES-128-GCM sealing the empty plaintext.
    // The `associated_data` is the pseudo-packet; `msg` is empty.
    let payload = Payload {
        msg: &[],
        aad: &pseudo,
    };
    let sealed = cipher.encrypt(nonce, payload).ok()?;
    // AES-128-GCM over empty plaintext produces only the 16-byte tag.
    if sealed.len() != 16 {
        return None;
    }
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&sealed);
    Some(tag)
}

/// Verify a received Retry packet's integrity tag (RFC 9001 §5.8).
///
/// * `odcid` — the original DCID the client sent in its first Initial
/// * `retry_packet` — the full Retry packet bytes (header + token + 16-byte tag)
///
/// Returns `true` if the tag is valid; `false` on truncation or tag mismatch.
#[must_use]
pub fn verify_retry_integrity_tag(odcid: &[u8], retry_packet: &[u8]) -> bool {
    if retry_packet.len() < 16 {
        return false;
    }
    let (without_tag, received_tag) = retry_packet.split_at(retry_packet.len() - 16);
    match compute_retry_integrity_tag(odcid, without_tag) {
        Some(computed) => {
            // Constant-time comparison to avoid timing oracles.
            let mut diff = 0u8;
            for (&a, &b) in computed.iter().zip(received_tag.iter()) {
                diff |= a ^ b;
            }
            diff == 0
        }
        None => false,
    }
}

/// Encode a Retry packet (RFC 9000 §17.2.5) and return it as a `Vec<u8>`.
///
/// * `scid` — server's source CID for this Retry (echoed back to client as SCID)
/// * `dcid` — client's DCID from the Initial (echoed as DCID)
/// * `odcid` — original DCID from the client's very first Initial (for integrity tag)
/// * `token` — opaque retry token the client must echo in its next Initial
///
/// Returns `None` if integrity tag computation fails.
#[must_use]
pub fn encode_retry_packet(
    scid: &[u8],
    dcid: &[u8],
    odcid: &[u8],
    token: &[u8],
) -> Option<Vec<u8>> {
    // Wire format (RFC 9000 §17.2.5):
    //   0b1111_0001 (Header Form=1, Fixed=1, Long Packet Type=0b11 Retry, Unused=0001)
    //   Version     4 bytes (QUIC v1 = 0x00000001)
    //   DCID Len    1 byte
    //   DCID        [dcid]
    //   SCID Len    1 byte
    //   SCID        [scid]
    //   Token       [token]  (no length prefix — runs to integrity tag)
    //   Tag         16 bytes integrity tag
    let mut buf = Vec::with_capacity(1 + 4 + 1 + dcid.len() + 1 + scid.len() + token.len() + 16);
    buf.push(0b1111_0001u8);
    buf.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    buf.push(dcid.len() as u8);
    buf.extend_from_slice(dcid);
    buf.push(scid.len() as u8);
    buf.extend_from_slice(scid);
    buf.extend_from_slice(token);

    let tag = compute_retry_integrity_tag(odcid, &buf)?;
    buf.extend_from_slice(&tag);
    Some(buf)
}

/// Parse a Retry packet, returning `(scid, dcid, token)` without the integrity tag,
/// or `None` if the packet is malformed or too short.
///
/// The caller is responsible for verifying the integrity tag via
/// [`verify_retry_integrity_tag`] before trusting the result.
#[must_use]
pub fn parse_retry_packet(datagram: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Minimum: 1(first) + 4(version) + 1(dcid_len) + 1(scid_len) + 16(tag) = 23
    if datagram.len() < 23 {
        return None;
    }
    let mut buf = Buf::new(datagram);
    let first = buf.get_u8().ok()?;
    // Long header (bit 7 = 1), long packet type bits 0x30 == 0b11_0000 = 0b11 (Retry).
    if first & 0x80 == 0 || (first & 0x30) != 0x30 {
        return None;
    }
    let version = buf.get_u32().ok()?;
    if version != 0x0000_0001 {
        return None;
    }
    let dcid_len = buf.get_u8().ok()? as usize;
    let dcid = buf.get_bytes(dcid_len).ok()?.to_vec();
    let scid_len = buf.get_u8().ok()? as usize;
    let scid = buf.get_bytes(scid_len).ok()?.to_vec();

    // Token is the remaining bytes minus the 16-byte tag.
    let consumed = buf.position();
    if datagram.len() < consumed + 16 {
        return None;
    }
    let token = datagram[consumed..datagram.len() - 16].to_vec();
    Some((scid, dcid, token))
}

/// Parse the token field from a client Initial packet without decrypting it.
/// Returns the raw token bytes (may be empty if no token was sent).
/// Returns `None` for malformed or truncated packets.
#[must_use]
pub fn parse_initial_token(datagram: &[u8]) -> Option<Vec<u8>> {
    use crate::coding::Buf;
    let first = *datagram.first()?;
    if first & 0x80 == 0 {
        return None; // short header
    }
    // Check this is an Initial packet (long packet type bits == 0b00).
    if (first & 0x30) != 0 {
        return None;
    }
    let mut buf = Buf::new(datagram);
    let _ = buf.get_u8().ok()?; // first byte
    let _version = buf.get_u32().ok()?; // version
    let dcid_len = buf.get_u8().ok()? as usize;
    let _ = buf.get_bytes(dcid_len).ok()?;
    let scid_len = buf.get_u8().ok()? as usize;
    let _ = buf.get_bytes(scid_len).ok()?;
    let token_len = buf.get_varint().ok()? as usize;
    let token = buf.get_bytes(token_len).ok()?.to_vec();
    Some(token)
}

/// Classify the first packet in a datagram without decrypting it: returns the
/// packet type and, for long headers, the destination connection ID. Used by an
/// endpoint to route an incoming datagram to a connection.
///
/// # Errors
/// Returns [`PacketError`] if the datagram is too short to classify.
pub fn peek_dcid(
    datagram: &[u8],
    short_dcid_len: usize,
) -> Result<(PacketType, Vec<u8>), PacketError> {
    let first = *datagram.first().ok_or(PacketError::Truncated)?;
    if first & 0x80 == 0 {
        // Short header: DCID immediately follows the first byte.
        let dcid = datagram
            .get(1..1 + short_dcid_len)
            .ok_or(PacketError::Truncated)?
            .to_vec();
        return Ok((PacketType::Short, dcid));
    }
    let mut buf = Buf::new(datagram);
    let _ = buf.get_u8()?;
    let version = buf.get_u32()?;
    let dcid_len = buf.get_u8()? as usize;
    let dcid = buf.get_bytes(dcid_len)?.to_vec();
    Ok((
        PacketType::from_first_byte_and_version(first, version),
        dcid,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxiquic_crypto::quic::AES128_GCM;
    use oxiquic_crypto::suites::tls13_aes_128_gcm_sha256_internal;
    use rustls::quic::{Keys, Version};
    use rustls::Side;

    fn initial_keys(side: Side) -> Keys {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        Keys::initial(
            Version::V1,
            tls13_aes_128_gcm_sha256_internal(),
            &AES128_GCM,
            &dcid,
            side,
        )
    }

    // A payload long enough to satisfy the 16-byte HP sample taken four bytes
    // past the start of the packet number.
    const SAMPLE_PAYLOAD: &[u8] = b"a sufficiently long crypto-frame payload for HP sampling";

    #[test]
    fn long_packet_roundtrip() {
        let client = initial_keys(Side::Client);
        let server = initial_keys(Side::Server);
        let payload = SAMPLE_PAYLOAD;
        let params = BuildLong {
            long_type: LongType::Initial,
            version: 1,
            dcid: &[1, 2, 3, 4],
            scid: &[5, 6, 7, 8],
            token: &[],
            packet_number: 0,
            largest_acked: None,
        };
        let mut datagram = Vec::new();
        build_long_packet(
            &mut datagram,
            &params,
            payload,
            client.local.packet.as_ref(),
            client.local.header.as_ref(),
        )
        .expect("build");

        let parsed = parse_long_packet(
            &mut datagram,
            0,
            1,
            None,
            server.remote.packet.as_ref(),
            server.remote.header.as_ref(),
        )
        .expect("parse");
        assert_eq!(parsed.packet_type, PacketType::Initial);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.packet_number, 0);
        assert_eq!(parsed.dcid, [1, 2, 3, 4]);
        assert_eq!(parsed.scid, [5, 6, 7, 8]);
        assert_eq!(parsed.consumed, datagram.len());
    }

    #[test]
    fn coalesced_long_packets_roundtrip() {
        // Two Initial packets (pn 0 and pn 1) coalesced into one datagram,
        // parsed back by advancing `offset` by `consumed`. Exercises the
        // start-relative HP math under a non-zero packet offset.
        let client = initial_keys(Side::Client);
        let server = initial_keys(Side::Server);
        let mut datagram = Vec::new();
        for pn in [0u64, 1] {
            let params = BuildLong {
                long_type: LongType::Initial,
                version: 1,
                dcid: &[1, 2, 3, 4],
                scid: &[5, 6, 7, 8],
                token: &[],
                packet_number: pn,
                largest_acked: None,
            };
            build_long_packet(
                &mut datagram,
                &params,
                SAMPLE_PAYLOAD,
                client.local.packet.as_ref(),
                client.local.header.as_ref(),
            )
            .expect("build");
        }

        let mut offset = 0;
        let mut seen = Vec::new();
        let mut largest = None;
        while offset < datagram.len() {
            let parsed = parse_long_packet(
                &mut datagram,
                offset,
                1,
                largest,
                server.remote.packet.as_ref(),
                server.remote.header.as_ref(),
            )
            .expect("parse coalesced");
            assert_eq!(parsed.payload, SAMPLE_PAYLOAD);
            seen.push(parsed.packet_number);
            largest = Some(parsed.packet_number);
            offset = parsed.consumed;
        }
        assert_eq!(seen, vec![0, 1]);
    }

    #[test]
    fn peek_dcid_long() {
        let params = BuildLong {
            long_type: LongType::Initial,
            version: 1,
            dcid: &[9, 9, 9],
            scid: &[1],
            token: &[],
            packet_number: 0,
            largest_acked: None,
        };
        let client = initial_keys(Side::Client);
        let mut datagram = Vec::new();
        build_long_packet(
            &mut datagram,
            &params,
            SAMPLE_PAYLOAD,
            client.local.packet.as_ref(),
            client.local.header.as_ref(),
        )
        .expect("build");
        let (typ, dcid) = peek_dcid(&datagram, 0).expect("peek");
        assert_eq!(typ, PacketType::Initial);
        assert_eq!(dcid, [9, 9, 9]);
    }
}
