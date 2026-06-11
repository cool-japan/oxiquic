//! Core types shared across the OxiQUIC stack.
//!
//! `oxiquic-core` is the dependency-free foundation of the COOLJAPAN Pure-Rust
//! QUIC implementation. It provides the RFC 9000 type system — stream and
//! connection identifiers, frame and packet classification, transport
//! parameters, version and error codes, and connection statistics — without
//! pulling in any transport, async runtime or cryptography dependency.
//!
//! These types are deliberately self-contained data types: every value here can
//! be constructed, inspected and validated without a network, which makes them
//! easy to test and reuse across `oxiquic-transport`, `oxiquic-h3` and the
//! `oxiquic` facade.
//!
//! # Examples
//!
//! ```
//! use oxiquic_core::{Direction, Initiator, StreamId};
//!
//! // The first client-initiated bidirectional stream is StreamId(0) per
//! // RFC 9000 Table 1.
//! let id = StreamId::new(Initiator::Client, Direction::Bidirectional, 0);
//! assert_eq!(id, StreamId(0));
//! assert_eq!(id.initiator(), Initiator::Client);
//! assert_eq!(id.direction(), Direction::Bidirectional);
//! assert_eq!(id.index(), 0);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod alpn;
mod connection_id;
mod error;
mod frame;
mod packet;
mod stats;
mod stream;
mod transport_error;
mod transport_params;
mod version;

pub use connection_id::{ConnectionId, MAX_CONNECTION_ID_LEN};
pub use error::OxiQuicError;
pub use frame::FrameType;
pub use packet::PacketType;
pub use stats::ConnectionStats;
pub use stream::{Direction, Initiator, StreamId};
pub use transport_error::TransportErrorCode;
pub use transport_params::{
    TransportParams, DEFAULT_ACK_DELAY_EXPONENT, DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    DEFAULT_MAX_ACK_DELAY_MS, DEFAULT_MAX_UDP_PAYLOAD_SIZE, MAX_ACK_DELAY_EXPONENT,
    MAX_ACK_DELAY_MS_LIMIT, MIN_ACTIVE_CONNECTION_ID_LIMIT, MIN_MAX_UDP_PAYLOAD_SIZE,
};
pub use version::QuicVersion;

#[cfg(test)]
mod tests;
