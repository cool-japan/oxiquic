//! Tokio `AsyncWrite` / `AsyncRead` stream handles for QUIC streams.
//!
//! [`SendStreamHandle`] and [`RecvStreamHandle`] are the write and read ends of
//! a QUIC bidirectional stream. They are obtained through
//! [`crate::endpoint::DrivenConnection::open_bidi_stream`] after calling
//! [`crate::endpoint::QuicConnection::into_driven`] on an established
//! [`crate::endpoint::QuicConnection`].
//!
//! The connection is serviced by a background [`tokio::task`] (the *driver*)
//! that owns the UDP socket and the [`crate::connection::Connection`] state
//! machine. Communication between the application and the driver uses bounded
//! [`tokio::sync::mpsc`] channels:
//!
//! - **write** — the application sends `(StreamId, WriteCmd)` tuples; the driver
//!   calls the connection's `send_stream` internal method and flushes datagrams.
//! - **open** — the application requests a new bidirectional stream; the driver
//!   calls the connection's `open_bidi` internal method and returns the
//!   `(StreamId, data_rx)` pair via a one-shot channel.
//! - **close** — the application requests graceful termination.
//! - **per-stream data** — for each open stream the driver maintains a `Sender<Vec<u8>>`
//!   in a [`std::collections::HashMap`]; when inbound STREAM frames arrive the
//!   data is forwarded to the matching channel.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use oxiquic_core::{OxiQuicError, StreamId};

/// Commands that the application can send to the driver for a specific stream.
///
/// Carried as `(StreamId, WriteCmd)` over the single write channel shared by
/// all streams on a connection.
#[derive(Debug)]
pub enum WriteCmd {
    /// Queue `data` for transmission, optionally finishing the stream.
    Write {
        /// The bytes to send.
        data: Vec<u8>,
        /// If `true`, mark the stream as finished (FIN bit).
        fin: bool,
    },
    /// Abruptly reset the stream with an application error code (RFC 9000 §19.4).
    Reset {
        /// Application-defined error code for the reset.
        error_code: u64,
    },
    /// Request the peer to stop sending on this stream (RFC 9000 §19.5).
    StopSending {
        /// Application-defined error code for the stop-sending request.
        error_code: u64,
    },
}

/// The channel type used to forward write commands to the driver.
///
/// Each message is `(stream_id, command)` so a single channel services all
/// streams on the connection.
pub type WriteTx = mpsc::Sender<(StreamId, WriteCmd)>;

// ─────────────────────────────────────────────────────────────────────────────
// SendStreamHandle
// ─────────────────────────────────────────────────────────────────────────────

/// Write end of a QUIC stream. Implements [`tokio::io::AsyncWrite`].
///
/// Obtained from [`crate::endpoint::DrivenConnection::open_bidi_stream`].
///
/// Dropping this handle without calling [`tokio::io::AsyncWriteExt::shutdown`]
/// leaves the stream half-open; call `shutdown` to flush the FIN.
pub struct SendStreamHandle {
    pub(crate) stream_id: StreamId,
    pub(crate) conn_tx: WriteTx,
}

impl SendStreamHandle {
    /// Abruptly reset this stream with an application error code, sending a
    /// `RESET_STREAM` frame to the peer (RFC 9000 §19.4).
    ///
    /// The peer's receive side will observe an error with the given `error_code`.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn reset(&self, error_code: u64) -> Result<(), OxiQuicError> {
        self.conn_tx
            .send((self.stream_id, WriteCmd::Reset { error_code }))
            .await
            .map_err(|_| OxiQuicError::Connection("stream closed".into()))
    }
}

impl AsyncWrite for SendStreamHandle {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let cmd = WriteCmd::Write {
            data: buf.to_vec(),
            fin: false,
        };
        match self.conn_tx.try_send((self.stream_id, cmd)) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel is full; wake us when capacity may be available and
                // return Pending. The waker is immediately notified (best
                // effort) because there is no direct hook into the channel's
                // available-capacity notification from a `try_send` path.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC driver task has been dropped",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flushing is handled by the background driver task; there is nothing
        // to do from the handle side.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Send a zero-length FIN to signal end-of-stream.
        let cmd = WriteCmd::Write {
            data: Vec::new(),
            fin: true,
        };
        // Ignore send errors: if the driver is gone the stream is already
        // closed, which is the desired outcome of shutdown.
        let _ = self.conn_tx.try_send((self.stream_id, cmd));
        Poll::Ready(Ok(()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecvStreamHandle
// ─────────────────────────────────────────────────────────────────────────────

/// Read end of a QUIC stream. Implements [`tokio::io::AsyncRead`].
///
/// Obtained from [`crate::endpoint::DrivenConnection::open_bidi_stream`] alongside
/// the matching [`SendStreamHandle`].
pub struct RecvStreamHandle {
    pub(crate) stream_id: StreamId,
    /// Inbound data chunks forwarded from the driver task.
    pub(crate) data_rx: mpsc::Receiver<Vec<u8>>,
    /// Leftover bytes from the last received chunk that did not fit into the
    /// caller's `ReadBuf`.
    pub(crate) buf: Vec<u8>,
    /// Cursor into `buf` indicating how many bytes have already been consumed.
    pub(crate) buf_pos: usize,
    /// Write channel shared with the driver — used to send `StopSending` frames.
    pub(crate) conn_tx: WriteTx,
}

impl RecvStreamHandle {
    /// The QUIC stream ID this handle reads from.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Send a `STOP_SENDING` frame to the peer, requesting they stop sending on
    /// this stream (RFC 9000 §19.5).
    ///
    /// The peer is expected to respond with a `RESET_STREAM` frame. The
    /// `error_code` is an application-defined value forwarded in the frame.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn stop_sending(&self, error_code: u64) -> Result<(), OxiQuicError> {
        self.conn_tx
            .send((self.stream_id, WriteCmd::StopSending { error_code }))
            .await
            .map_err(|_| OxiQuicError::Connection("stream closed".into()))
    }

    /// Consume this handle and return the underlying data receiver channel.
    ///
    /// Used by the `h3-compat` layer to poll for inbound data chunks directly,
    /// bypassing the `AsyncRead` adaptor and its internal leftover buffer.
    #[cfg(feature = "h3-compat")]
    pub(crate) fn into_data_rx(self) -> mpsc::Receiver<Vec<u8>> {
        self.data_rx
    }
}

impl AsyncRead for RecvStreamHandle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Fast path: leftover bytes from the previous chunk.
        if self.buf_pos < self.buf.len() {
            let available = &self.buf[self.buf_pos..];
            let to_copy = available.len().min(dst.remaining());
            dst.put_slice(&available[..to_copy]);
            self.buf_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // No leftover; wait for the next chunk from the driver.
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = data.len().min(dst.remaining());
                dst.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    // Store overflow for the next poll_read call.
                    self.buf = data;
                    self.buf_pos = to_copy;
                } else {
                    // All bytes consumed; clear the buffer.
                    self.buf.clear();
                    self.buf_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed — the driver is gone or the stream ended.
                // Signal EOF to the caller.
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BiStream
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// UniSendStream
// ─────────────────────────────────────────────────────────────────────────────

/// A unidirectional QUIC send-only stream (local-initiated, write-only).
///
/// Wraps a [`SendStreamHandle`] with a type that makes the unidirectional
/// nature explicit in the API surface.  All [`AsyncWrite`] methods delegate
/// to the inner handle.
pub struct UniSendStream {
    /// The underlying write handle.
    pub inner: SendStreamHandle,
}

impl UniSendStream {
    /// Wrap a [`SendStreamHandle`] as a typed unidirectional send stream.
    #[must_use]
    pub fn new(inner: SendStreamHandle) -> Self {
        Self { inner }
    }

    /// The QUIC stream ID of this unidirectional stream.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.inner.stream_id
    }

    /// Write `data` to the stream.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the driver task has stopped.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, OxiQuicError> {
        self.inner.write(data).await.map_err(OxiQuicError::Io)
    }

    /// Finish the stream by flushing a FIN to the peer.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the driver task has stopped.
    pub async fn finish(&mut self) -> Result<(), OxiQuicError> {
        self.inner.shutdown().await.map_err(OxiQuicError::Io)
    }

    /// Abruptly reset this unidirectional send stream with an application error
    /// code, sending a `RESET_STREAM` frame to the peer (RFC 9000 §19.4).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn reset(&self, error_code: u64) -> Result<(), OxiQuicError> {
        self.inner.reset(error_code).await
    }
}

impl AsyncWrite for UniSendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UniRecvStream
// ─────────────────────────────────────────────────────────────────────────────

/// A unidirectional QUIC receive-only stream (peer-initiated, read-only).
///
/// Wraps a [`RecvStreamHandle`] with a type that makes the unidirectional
/// receive nature explicit in the API surface.  All [`AsyncRead`] methods
/// delegate to the inner handle.
pub struct UniRecvStream {
    /// The underlying read handle.
    pub inner: RecvStreamHandle,
}

impl UniRecvStream {
    /// Wrap a [`RecvStreamHandle`] as a typed unidirectional receive stream.
    #[must_use]
    pub fn new(inner: RecvStreamHandle) -> Self {
        Self { inner }
    }

    /// The QUIC stream ID of this unidirectional stream.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.inner.stream_id()
    }

    /// Read up to `buf.len()` bytes from the stream.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the driver task has stopped or the
    /// stream was reset.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, OxiQuicError> {
        self.inner.read(buf).await.map_err(OxiQuicError::Io)
    }

    /// Send a `STOP_SENDING` frame to the peer on this receive stream,
    /// requesting they stop sending (RFC 9000 §19.5).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn stop_sending(&self, error_code: u64) -> Result<(), OxiQuicError> {
        self.inner.stop_sending(error_code).await
    }
}

impl AsyncRead for UniRecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BiStream
// ─────────────────────────────────────────────────────────────────────────────

/// A bidirectional QUIC stream combining a send and receive half.
///
/// Obtained from [`crate::endpoint::DrivenConnection::open_bidi_stream`] via
/// [`crate::endpoint::DrivenConnection::open_bidi`], or constructed from a
/// `(SendStreamHandle, RecvStreamHandle)` pair.
///
/// Both halves implement [`tokio::io::AsyncWrite`] / [`tokio::io::AsyncRead`]
/// respectively; `BiStream` wraps them with convenience methods for the common
/// request/response pattern.
pub struct BiStream {
    /// Send half of the bidirectional stream.
    pub send: SendStreamHandle,
    /// Receive half of the bidirectional stream.
    pub recv: RecvStreamHandle,
}

impl BiStream {
    /// Create a `BiStream` from its constituent send and receive halves.
    #[must_use]
    pub fn new(send: SendStreamHandle, recv: RecvStreamHandle) -> Self {
        Self { send, recv }
    }

    /// Write `data` to the send half of the stream.
    ///
    /// Delegates to [`tokio::io::AsyncWriteExt::write`] on the inner
    /// [`SendStreamHandle`].
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the driver task has stopped.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, OxiQuicError> {
        self.send.write(data).await.map_err(OxiQuicError::Io)
    }

    /// Read up to `buf.len()` bytes from the receive half of the stream.
    ///
    /// Delegates to [`tokio::io::AsyncReadExt::read`] on the inner
    /// [`RecvStreamHandle`].
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the driver task has stopped or the
    /// stream was reset.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, OxiQuicError> {
        self.recv.read(buf).await.map_err(OxiQuicError::Io)
    }

    /// Finish the send half by flushing a FIN to the peer.
    ///
    /// Equivalent to calling [`tokio::io::AsyncWriteExt::shutdown`] on the
    /// inner [`SendStreamHandle`].
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the driver task has stopped.
    pub async fn finish(&mut self) -> Result<(), OxiQuicError> {
        self.send.shutdown().await.map_err(OxiQuicError::Io)
    }

    /// The QUIC stream ID shared by both halves.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.recv.stream_id()
    }

    /// Abruptly reset the send half of this stream with an application error
    /// code (RFC 9000 §19.4).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn reset(&self, error_code: u64) -> Result<(), OxiQuicError> {
        self.send.reset(error_code).await
    }

    /// Send a `STOP_SENDING` frame to the peer on the receive half of this
    /// stream, requesting they stop sending (RFC 9000 §19.5).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn stop_sending(&self, error_code: u64) -> Result<(), OxiQuicError> {
        self.recv.stop_sending(error_code).await
    }
}
