//! QUIC packet types (RFC 9000 Section 17).

use std::fmt;

/// The type of a QUIC packet, distinguished by its header form and — for
/// long-header packets — the two-bit type field (RFC 9000 Section 17).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PacketType {
    /// Long-header `Initial` packet (type bits `0b00`), carrying the first
    /// `CRYPTO` frames of the handshake (RFC 9000 Section 17.2.2).
    Initial,
    /// Long-header `0-RTT` packet (type bits `0b01`), carrying early data
    /// (RFC 9000 Section 17.2.3).
    ZeroRtt,
    /// Long-header `Handshake` packet (type bits `0b10`)
    /// (RFC 9000 Section 17.2.4).
    Handshake,
    /// Long-header `Retry` packet (type bits `0b11`)
    /// (RFC 9000 Section 17.2.5).
    Retry,
    /// A Version Negotiation packet: long header with a `Version` field of
    /// zero (RFC 9000 Section 17.2.1).
    VersionNegotiation,
    /// A short-header (1-RTT) packet (RFC 9000 Section 17.3).
    Short,
}

impl PacketType {
    /// Classify a packet from its first byte.
    ///
    /// This inspects only the header-form bit (`0x80`) and, for long headers,
    /// the QUIC v1 long-packet-type bits (`0x30`). It cannot distinguish a
    /// Version Negotiation packet — that requires reading the `Version` field —
    /// so a long-header first byte never yields
    /// [`PacketType::VersionNegotiation`]; use
    /// [`PacketType::from_first_byte_and_version`] when the version is known.
    #[must_use]
    pub const fn from_first_byte(first_byte: u8) -> Self {
        // Bit 0x80 is the header form: 1 = long header, 0 = short header.
        if first_byte & 0x80 == 0 {
            return Self::Short;
        }
        // Long header: bits 0x30 select the packet type (QUIC v1).
        match (first_byte & 0x30) >> 4 {
            0b00 => Self::Initial,
            0b01 => Self::ZeroRtt,
            0b10 => Self::Handshake,
            _ => Self::Retry,
        }
    }

    /// Classify a packet from its first byte and the long-header `Version`
    /// field (ignored for short headers).
    ///
    /// A long-header packet whose version is `0` is a Version Negotiation
    /// packet regardless of its type bits (RFC 9000 Section 17.2.1).
    #[must_use]
    pub const fn from_first_byte_and_version(first_byte: u8, version: u32) -> Self {
        if first_byte & 0x80 != 0 && version == 0 {
            return Self::VersionNegotiation;
        }
        Self::from_first_byte(first_byte)
    }

    /// Returns `true` if this packet uses the long header form
    /// (everything except [`PacketType::Short`]).
    #[must_use]
    pub const fn is_long_header(self) -> bool {
        !matches!(self, Self::Short)
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Initial => "Initial",
            Self::ZeroRtt => "0-RTT",
            Self::Handshake => "Handshake",
            Self::Retry => "Retry",
            Self::VersionNegotiation => "VersionNegotiation",
            Self::Short => "1-RTT",
        })
    }
}
