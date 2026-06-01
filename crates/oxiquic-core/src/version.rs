//! QUIC version identifiers (RFC 9000 / RFC 9369).

use std::fmt;

/// A QUIC version number as carried in the long-header `Version` field.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum QuicVersion {
    /// QUIC version 1, `0x00000001` (RFC 9000).
    V1,
    /// QUIC version 2, `0x6b3343cf` (RFC 9369).
    V2,
    /// The reserved value `0x00000000`, which signals a Version Negotiation
    /// packet (RFC 9000 Section 17.2.1).
    Negotiation,
    /// Any other (unrecognized or experimental) version number.
    Unknown(u32),
}

impl QuicVersion {
    /// The wire value for QUIC version 1 (RFC 9000).
    pub const V1_VALUE: u32 = 0x0000_0001;
    /// The wire value for QUIC version 2 (RFC 9369).
    pub const V2_VALUE: u32 = 0x6b33_43cf;
    /// The wire value reserved for Version Negotiation packets.
    pub const NEGOTIATION_VALUE: u32 = 0x0000_0000;

    /// Decode a [`QuicVersion`] from its 32-bit wire value.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        match value {
            Self::V1_VALUE => Self::V1,
            Self::V2_VALUE => Self::V2,
            Self::NEGOTIATION_VALUE => Self::Negotiation,
            other => Self::Unknown(other),
        }
    }

    /// The 32-bit wire value for this version.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        match self {
            Self::V1 => Self::V1_VALUE,
            Self::V2 => Self::V2_VALUE,
            Self::Negotiation => Self::NEGOTIATION_VALUE,
            Self::Unknown(value) => value,
        }
    }

    /// Returns `true` if this is a version OxiQUIC recognizes as a real,
    /// usable QUIC version (currently v1 and v2).
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::V1 | Self::V2)
    }

    /// Returns `true` if a long-header packet carrying this version value is a
    /// Version Negotiation packet (RFC 9000 Section 6).
    #[must_use]
    pub const fn is_negotiation(self) -> bool {
        matches!(self, Self::Negotiation)
    }
}

impl fmt::Display for QuicVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => f.write_str("QUICv1"),
            Self::V2 => f.write_str("QUICv2"),
            Self::Negotiation => f.write_str("version-negotiation"),
            Self::Unknown(value) => write!(f, "QUIC(0x{value:08x})"),
        }
    }
}

impl From<u32> for QuicVersion {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<QuicVersion> for u32 {
    fn from(version: QuicVersion) -> Self {
        version.to_u32()
    }
}
