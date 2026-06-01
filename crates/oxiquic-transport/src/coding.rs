//! Wire codecs for QUIC: variable-length integers (RFC 9000 Section 16) and
//! packet-number encoding/decoding (RFC 9000 Section 17.1, Appendix A).
//!
//! These are the lowest-level primitives the packet and frame coders build on.
//! All decoders operate over a [`Buf`] cursor that tracks the read position and
//! reports a [`CodecError`] (rather than panicking) when input is truncated or
//! malformed, satisfying the no-panic policy for production code.

use oxiquic_core::OxiQuicError;

/// The largest value representable by a 62-bit QUIC variable-length integer.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// An error decoding a QUIC wire structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The buffer ended before the structure was fully read.
    UnexpectedEnd,
    /// A value did not fit the field it was encoded into (e.g. a varint above
    /// `2^62 - 1`).
    Malformed(&'static str),
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEnd => f.write_str("unexpected end of buffer"),
            Self::Malformed(why) => write!(f, "malformed encoding: {why}"),
        }
    }
}

impl From<CodecError> for OxiQuicError {
    fn from(err: CodecError) -> Self {
        Self::FrameEncoding(err.to_string())
    }
}

/// The number of bytes a variable-length integer occupies for a given value.
#[must_use]
pub const fn varint_size(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

/// A read cursor over a byte slice with QUIC-aware decoders.
#[derive(Debug, Clone)]
pub struct Buf<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Buf<'a> {
    /// Wrap a byte slice in a cursor positioned at the start.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// The number of bytes remaining to be read.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// Whether the cursor has consumed all input.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The current read offset from the start of the slice.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read a single byte.
    ///
    /// # Errors
    /// Returns [`CodecError::UnexpectedEnd`] if no bytes remain.
    pub fn get_u8(&mut self) -> Result<u8, CodecError> {
        let byte = *self.bytes.get(self.pos).ok_or(CodecError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(byte)
    }

    /// Read a big-endian `u16`.
    ///
    /// # Errors
    /// Returns [`CodecError::UnexpectedEnd`] if fewer than two bytes remain.
    pub fn get_u16(&mut self) -> Result<u16, CodecError> {
        let hi = u16::from(self.get_u8()?);
        let lo = u16::from(self.get_u8()?);
        Ok((hi << 8) | lo)
    }

    /// Read a big-endian `u32`.
    ///
    /// # Errors
    /// Returns [`CodecError::UnexpectedEnd`] if fewer than four bytes remain.
    pub fn get_u32(&mut self) -> Result<u32, CodecError> {
        let hi = u32::from(self.get_u16()?);
        let lo = u32::from(self.get_u16()?);
        Ok((hi << 16) | lo)
    }

    /// Borrow `len` bytes without copying, advancing the cursor.
    ///
    /// # Errors
    /// Returns [`CodecError::UnexpectedEnd`] if fewer than `len` bytes remain.
    pub fn get_bytes(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(len).ok_or(CodecError::UnexpectedEnd)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(CodecError::UnexpectedEnd)?;
        self.pos = end;
        Ok(slice)
    }

    /// Decode a QUIC variable-length integer (RFC 9000 Section 16).
    ///
    /// # Errors
    /// Returns [`CodecError::UnexpectedEnd`] if the buffer ends mid-value.
    pub fn get_varint(&mut self) -> Result<u64, CodecError> {
        let first = self.get_u8()?;
        // The two most-significant bits of the first byte give the length.
        let len_log = first >> 6;
        let mut value = u64::from(first & 0x3f);
        let extra = (1usize << len_log) - 1;
        for _ in 0..extra {
            value = (value << 8) | u64::from(self.get_u8()?);
        }
        Ok(value)
    }
}

/// Append a QUIC variable-length integer to `out`.
///
/// Values above [`VARINT_MAX`] are clamped to the maximum 62-bit value; callers
/// holding genuinely larger numbers are protocol-violating and validated
/// elsewhere.
pub fn put_varint(out: &mut Vec<u8>, value: u64) {
    let value = value.min(VARINT_MAX);
    match varint_size(value) {
        1 => out.push(value as u8),
        2 => {
            out.push(0x40 | ((value >> 8) as u8));
            out.push(value as u8);
        }
        4 => {
            out.push(0x80 | ((value >> 24) as u8));
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        _ => {
            out.push(0xc0 | ((value >> 56) as u8));
            out.push((value >> 48) as u8);
            out.push((value >> 40) as u8);
            out.push((value >> 32) as u8);
            out.push((value >> 24) as u8);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
    }
}

/// The minimum number of bytes needed to encode `pn` given the largest packet
/// number acknowledged so far (`largest_acked`), per RFC 9000 Appendix A.2.
///
/// QUIC requires enough bits to unambiguously recover the packet number; we
/// pick the smallest of 1..=4 bytes that covers twice the in-flight range.
#[must_use]
pub fn packet_number_len(pn: u64, largest_acked: Option<u64>) -> usize {
    let range = match largest_acked {
        Some(acked) => pn.saturating_sub(acked).saturating_mul(2),
        // No prior ACK: encode the full magnitude.
        None => pn.saturating_add(1).saturating_mul(2),
    };
    if range < (1 << 8) {
        1
    } else if range < (1 << 16) {
        2
    } else if range < (1 << 24) {
        3
    } else {
        4
    }
}

/// Encode the low `len` bytes of `pn` in big-endian order (RFC 9000 Section
/// 17.1). `len` must be in `1..=4`.
pub fn encode_packet_number(out: &mut Vec<u8>, pn: u64, len: usize) {
    let len = len.clamp(1, 4);
    for shift in (0..len).rev() {
        out.push((pn >> (shift * 8)) as u8);
    }
}

/// Decode a truncated packet number against the largest received packet number,
/// recovering the full 62-bit value (RFC 9000 Appendix A.3).
///
/// `truncated` holds the wire bits, `pn_len` their count in bytes, and
/// `largest_pn` the largest packet number successfully processed in this space
/// (or `None` if none yet).
#[must_use]
pub fn decode_packet_number(largest_pn: Option<u64>, truncated: u64, pn_len: usize) -> u64 {
    let expected = match largest_pn {
        Some(largest) => largest + 1,
        None => 0,
    };
    let pn_nbits = (pn_len * 8) as u32;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    let candidate = (expected & !pn_mask) | truncated;
    // Choose the candidate closest to `expected`, breaking ties downward, while
    // never producing a negative value (RFC 9000 Appendix A.3 pseudocode).
    if candidate.wrapping_add(pn_hwin) <= expected
        && candidate < (u64::MAX - pn_win)
        && expected.saturating_sub(candidate) > pn_hwin
    {
        return candidate + pn_win;
    }
    if candidate > expected + pn_hwin && candidate >= pn_win {
        return candidate - pn_win;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_all_lengths() {
        for value in [0u64, 63, 64, 16383, 16384, 1 << 29, 1 << 30, VARINT_MAX] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            assert_eq!(out.len(), varint_size(value));
            let mut buf = Buf::new(&out);
            assert_eq!(buf.get_varint().expect("decode"), value);
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn varint_known_vectors() {
        // RFC 9000 Section 16 sample encodings.
        let mut out = Vec::new();
        put_varint(&mut out, 37);
        assert_eq!(out, [0x25]);
        out.clear();
        put_varint(&mut out, 15293);
        assert_eq!(out, [0x7b, 0xbd]);
        out.clear();
        put_varint(&mut out, 494_878_333);
        assert_eq!(out, [0x9d, 0x7f, 0x3e, 0x7d]);
    }

    #[test]
    fn truncated_varint_errors() {
        let mut buf = Buf::new(&[0x40]); // 2-byte varint missing its second byte
        assert_eq!(buf.get_varint(), Err(CodecError::UnexpectedEnd));
    }

    #[test]
    fn packet_number_roundtrip() {
        let largest = Some(0xa82f30ea);
        let pn = 0xa82f30eb;
        let len = packet_number_len(pn, largest);
        let mut out = Vec::new();
        encode_packet_number(&mut out, pn, len);
        let mut truncated = 0u64;
        for &b in &out {
            truncated = (truncated << 8) | u64::from(b);
        }
        assert_eq!(decode_packet_number(largest, truncated, len), pn);
    }

    #[test]
    fn packet_number_wraps_window() {
        // RFC 9000 Appendix A.3 worked example.
        let largest = Some(0xa82f30ea);
        let decoded = decode_packet_number(largest, 0x9b32, 2);
        assert_eq!(decoded, 0xa82f9b32);
    }

    #[test]
    fn first_packet_number_no_ack() {
        let len = packet_number_len(0, None);
        let mut out = Vec::new();
        encode_packet_number(&mut out, 0, len);
        let mut truncated = 0u64;
        for &b in &out {
            truncated = (truncated << 8) | u64::from(b);
        }
        assert_eq!(decode_packet_number(None, truncated, len), 0);
    }
}
