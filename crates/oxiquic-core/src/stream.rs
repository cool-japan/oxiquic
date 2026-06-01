//! QUIC stream identifiers and their RFC 9000 Section 2.1 semantics.

use std::fmt;

/// Which endpoint initiated a stream (RFC 9000 Section 2.1, bit 0x1 of the ID).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Initiator {
    /// The client initiated the stream (low bit `0`).
    Client,
    /// The server initiated the stream (low bit `1`).
    Server,
}

impl fmt::Display for Initiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Client => "client",
            Self::Server => "server",
        })
    }
}

/// Which directions data flows in a stream (RFC 9000 Section 2.1, bit 0x2 of the ID).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Data flows in both directions (bit `0`).
    Bidirectional,
    /// Data flows in one direction only (bit `1`).
    Unidirectional,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bidirectional => "bidirectional",
            Self::Unidirectional => "unidirectional",
        })
    }
}

/// A QUIC stream identifier (RFC 9000 Section 2.1).
///
/// The 62-bit value encodes three fields:
///
/// | bits   | meaning                                    |
/// |--------|--------------------------------------------|
/// | `0x1`  | initiator: `0` = client, `1` = server      |
/// | `0x2`  | direction: `0` = bidirectional, `1` = uni  |
/// | `>> 2` | the stream index within its `(initiator, direction)` class |
///
/// Per RFC 9000 Table 1, `StreamId(0)` is the first client-initiated
/// bidirectional stream and `StreamId(3)` is the first server-initiated
/// unidirectional stream.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u64);

impl StreamId {
    /// The maximum legal stream index, given the 62-bit varint encoding of the
    /// stream ID (RFC 9000 Section 16): `2^60 - 1`.
    pub const MAX_INDEX: u64 = (1 << 60) - 1;

    /// Compose a stream ID from its initiator, direction and index.
    ///
    /// The `index` is masked to 60 bits so the resulting value always fits the
    /// 62-bit stream-ID space.
    #[must_use]
    pub const fn new(initiator: Initiator, direction: Direction, index: u64) -> Self {
        let initiator_bit = match initiator {
            Initiator::Client => 0,
            Initiator::Server => 1,
        };
        let direction_bit = match direction {
            Direction::Bidirectional => 0,
            Direction::Unidirectional => 1,
        };
        let index = index & Self::MAX_INDEX;
        Self((index << 2) | (direction_bit << 1) | initiator_bit)
    }

    /// Returns the raw 62-bit stream-ID value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Which endpoint initiated the stream (bit `0x1`).
    #[must_use]
    pub const fn initiator(self) -> Initiator {
        if self.0 & 0x1 == 0 {
            Initiator::Client
        } else {
            Initiator::Server
        }
    }

    /// Which directions data flows in the stream (bit `0x2`).
    #[must_use]
    pub const fn direction(self) -> Direction {
        if self.0 & 0x2 == 0 {
            Direction::Bidirectional
        } else {
            Direction::Unidirectional
        }
    }

    /// The stream index within its `(initiator, direction)` class (bits `>> 2`).
    #[must_use]
    pub const fn index(self) -> u64 {
        self.0 >> 2
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} stream {}",
            self.initiator(),
            self.direction(),
            self.index()
        )
    }
}

impl From<u64> for StreamId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<StreamId> for u64 {
    fn from(value: StreamId) -> Self {
        value.0
    }
}
