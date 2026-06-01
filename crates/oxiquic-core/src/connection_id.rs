//! QUIC connection identifiers (RFC 9000 Section 5.1 / 17.2).

use crate::error::OxiQuicError;
use smallvec::SmallVec;
use std::fmt;

/// The maximum length, in bytes, of a connection ID carried in a long header
/// (RFC 9000 Section 17.2). Short-header (1-RTT) packets do not encode a length,
/// so the local endpoint chooses a fixed length; this bound still applies.
pub const MAX_CONNECTION_ID_LEN: usize = 20;

/// A QUIC connection identifier: a variable-length (0–20 byte) opaque label
/// used to route packets to a connection independent of the network 4-tuple.
///
/// The inner bytes are stored in a `SmallVec<[u8; 20]>` to avoid heap
/// allocation for the full legal size range (0–20 bytes).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct ConnectionId(SmallVec<[u8; 20]>);

impl ConnectionId {
    /// Construct a connection ID from raw bytes without validating the length.
    ///
    /// Prefer [`ConnectionId::try_new`] when the input is untrusted.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(SmallVec::from_vec(bytes.into()))
    }

    /// Construct a connection ID, rejecting inputs longer than
    /// [`MAX_CONNECTION_ID_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OxiQuicError::Protocol`] if the input exceeds 20 bytes.
    pub fn try_new(bytes: impl Into<Vec<u8>>) -> Result<Self, OxiQuicError> {
        let cid = Self(SmallVec::from_vec(bytes.into()));
        cid.validate()?;
        Ok(cid)
    }

    /// The length of the connection ID in bytes (`0..=20`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if this is the zero-length connection ID.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The raw connection-ID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Verify that the connection ID is at most [`MAX_CONNECTION_ID_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OxiQuicError::Protocol`] if the ID is longer than 20 bytes,
    /// which would be a `PROTOCOL_VIOLATION` per RFC 9000 Section 17.2.
    pub fn validate(&self) -> Result<(), OxiQuicError> {
        if self.0.len() > MAX_CONNECTION_ID_LEN {
            return Err(OxiQuicError::Protocol(format!(
                "connection ID length {} exceeds maximum of {MAX_CONNECTION_ID_LEN} bytes",
                self.0.len()
            )));
        }
        Ok(())
    }
}

impl From<Vec<u8>> for ConnectionId {
    fn from(bytes: Vec<u8>) -> Self {
        Self(SmallVec::from_vec(bytes))
    }
}

impl From<&[u8]> for ConnectionId {
    fn from(bytes: &[u8]) -> Self {
        Self(SmallVec::from_slice(bytes))
    }
}

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionId({self})")
    }
}

impl fmt::Display for ConnectionId {
    /// Renders the connection ID as lowercase hex, e.g. `0a1b2c3d`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
