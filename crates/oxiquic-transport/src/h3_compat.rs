//! h3 QUIC trait adapters for OxiQUIC streams.
//!
//! This module bridges [`SendStreamHandle`] / [`RecvStreamHandle`] (the
//! tokio `AsyncWrite` / `AsyncRead` stream handles produced by a
//! [`DrivenConnection`]) to the
//! [`h3::quic`] trait layer so that the `h3` crate can drive HTTP/3 framing
//! over OxiQUIC streams.
//!
//! # Usage
//!
//! After obtaining a `(SendStreamHandle, RecvStreamHandle)` pair from
//! [`DrivenConnection::open_bidi_stream`][crate::endpoint::DrivenConnection::open_bidi_stream],
//! wrap them in [`H3BidiStream::new`] to get an object that implements
//! [`h3::quic::BidiStream`], [`h3::quic::SendStream`], and
//! [`h3::quic::RecvStream`]:
//!
//! ```ignore
//! let (send, recv) = conn.open_bidi_stream().await?;
//! let bidi = H3BidiStream::new(send, recv);
//! // Pass `bidi` to h3::client::SendRequest::send_request etc.
//! ```
//!
//! # Backpressure
//!
//! `poll_ready` reserves a slot in the connection-wide write channel using
//! `reserve_owned()`. The permit is held until `send_data` consumes it, at
//! which point the send is infallible.
//!
//! **Known limitation:** the write channel is connection-wide (256 slots
//! shared across ALL streams on the connection). A permit held between
//! `poll_ready` and `send_data` reserves one connection-wide slot. This means
//! a stalled stream can head-of-line block sibling streams. True per-stream
//! backpressure requires per-stream channels and is out of scope for this
//! adapter.

#![cfg(feature = "h3-compat")]

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::sync::mpsc;

use h3::quic::StreamId as H3StreamId;
use h3::quic::{BidiStream, RecvStream, SendStream, StreamErrorIncoming, WriteBuf};
use h3::quic::{ConnectionErrorIncoming, OpenStreams};

use crate::endpoint::DrivenConnection;
use crate::handle::{RecvStreamHandle, SendStreamHandle, WriteCmd};
use oxiquic_core::{OxiQuicError, StreamId};

// ─────────────────────────────────────────────────────────────────────────────
// Type aliases to avoid clippy::type_complexity warnings
// ─────────────────────────────────────────────────────────────────────────────

/// An owned permit on the connection write channel, ready to send one message
/// infallibly.
type WritePermit = mpsc::OwnedPermit<(StreamId, WriteCmd)>;

/// In-flight future that reserves a [`WritePermit`] on the connection channel.
type ReserveFut =
    Pin<Box<dyn Future<Output = Result<WritePermit, mpsc::error::SendError<()>>> + Send>>;

// ─────────────────────────────────────────────────────────────────────────────
// StreamId conversion helper
// ─────────────────────────────────────────────────────────────────────────────

/// Convert an OxiQUIC [`StreamId`] to an h3 [`H3StreamId`].
///
/// Both types store a 62-bit QUIC stream ID as a `u64`. The conversion can only
/// fail when the value exceeds the QUIC VarInt ceiling (2^62 − 1); since
/// OxiQUIC enforces the same ceiling in `StreamId::MAX_INDEX`, this conversion
/// will succeed for any `StreamId` produced by OxiQUIC.
///
/// In the unlikely event that an out-of-range value is encountered the
/// `StreamErrorIncoming::Unknown` variant is used by callers that cannot
/// propagate an error, and a `Result` is returned from constructors.
fn convert_stream_id(id: StreamId) -> Result<H3StreamId, StreamErrorIncoming> {
    H3StreamId::try_from(id.as_u64()).map_err(|e| {
        StreamErrorIncoming::Unknown(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "OxiQUIC stream id {} out of h3 VarInt range: {}",
                id.as_u64(),
                e
            ),
        )))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// H3SendStream
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a [`SendStreamHandle`] and implements [`h3::quic::SendStream`].
///
/// # Backpressure design
///
/// `poll_ready` drives an in-flight `reserve_owned()` future stored in
/// `reserve_fut`. The future is created once and kept alive across `Pending`
/// returns so its waiter node stays registered in the channel's semaphore
/// wait-list — re-creating the future on every poll would deregister the
/// waiter, causing a lost-wakeup bug where the task never gets re-polled after
/// capacity is freed.
///
/// Once a `WritePermit` is obtained it is stored in `pending_permit`. The next
/// call to `send_data` consumes the permit with an infallible `permit.send()`,
/// satisfying the h3 contract that `send_data` must not fail after `poll_ready`
/// returned `Ready(Ok(()))`.
///
/// `poll_finish` uses the same permit-reservation pattern via `fin_reserve_fut`
/// to guarantee the FIN frame is delivered even when the write channel is under
/// pressure.  Using `try_send` for FIN (the previous approach) silently dropped
/// the frame on a full channel, causing the peer's `recv_data` to hang
/// indefinitely while waiting for stream end.
///
/// **Connection-wide HoL caveat:** the write channel is shared across all
/// streams on the connection. A permit held between `poll_ready` and
/// `send_data` occupies one connection-wide slot, so a stalled stream can
/// head-of-line block sibling streams. Per-stream channels are out of scope.
pub struct H3SendStream {
    inner: SendStreamHandle,
    /// Pre-converted h3 stream ID. Stored to avoid fallible conversion on every
    /// call to `send_id`.
    h3_id: H3StreamId,
    /// A channel permit reserved by `poll_ready`, consumed infallibly by
    /// `send_data`. `None` means `poll_ready` has not yet been called (or
    /// `send_data` already consumed the permit).
    pending_permit: Option<WritePermit>,
    /// In-flight `reserve_owned()` future. Kept alive across `Pending` returns
    /// so its waiter node stays registered in the channel semaphore.
    reserve_fut: Option<ReserveFut>,
    /// In-flight `reserve_owned()` future used exclusively by `poll_finish`.
    /// Kept alive across `Pending` returns for the same lost-wakeup reasons as
    /// `reserve_fut`.
    fin_reserve_fut: Option<ReserveFut>,
}

impl H3SendStream {
    /// Wrap a [`SendStreamHandle`].
    ///
    /// # Errors
    ///
    /// Returns [`StreamErrorIncoming::Unknown`] if the underlying stream id
    /// exceeds the QUIC VarInt ceiling (2^62 − 1).
    pub fn new(inner: SendStreamHandle) -> Result<Self, StreamErrorIncoming> {
        let h3_id = convert_stream_id(inner.stream_id)?;
        Ok(Self {
            inner,
            h3_id,
            pending_permit: None,
            reserve_fut: None,
            fin_reserve_fut: None,
        })
    }
}

impl<B: Buf> SendStream<B> for H3SendStream {
    /// Reserve a slot in the connection write channel and report readiness.
    ///
    /// This drives an `OwnedPermit` reservation future. The future is stored in
    /// `self.reserve_fut` across `Pending` returns so its waiter node stays
    /// registered — if the future were re-created on every poll the waker
    /// would be deregistered on every `Pending`, causing a lost-wakeup.
    ///
    /// Once a permit is obtained it is placed in `self.pending_permit` and
    /// `Ready(Ok(()))` is returned. A double-poll guard (`pending_permit` is
    /// already `Some`) short-circuits immediately.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        // Fast path: a permit is already reserved from a prior call.
        if self.pending_permit.is_some() {
            return Poll::Ready(Ok(()));
        }

        // Ensure an in-flight reservation future exists.
        if self.reserve_fut.is_none() {
            self.reserve_fut = Some(Box::pin(self.inner.conn_tx.clone().reserve_owned()));
        }

        // Drive the reservation future. The future stays alive in `reserve_fut`
        // while it returns `Pending` so its waiter node is not dropped.
        let fut = self
            .reserve_fut
            .as_mut()
            .expect("reserve_fut was just set above if None");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                self.reserve_fut = None;
                self.pending_permit = Some(permit);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                self.reserve_fut = None;
                Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "OxiQUIC driver task has been dropped",
                    ),
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Encode `data` to wire format and enqueue it on the write channel.
    ///
    /// `WriteBuf<B>` implements [`bytes::Buf`]; we drain it via `chunk` /
    /// `advance` into a contiguous `Vec<u8>` and forward it to the driver.
    ///
    /// If `poll_ready` previously returned `Ready(Ok(()))` then a
    /// write permit is already held; we consume it with an infallible
    /// `permit.send()`. If `send_data` is called without a prior `poll_ready`
    /// (a contract violation by the caller) we fall back to `try_send` and
    /// return `WouldBlock` when the channel is full.
    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        let mut write_buf = data.into();
        let mut payload: Vec<u8> = Vec::with_capacity(write_buf.remaining());
        while write_buf.has_remaining() {
            let chunk = write_buf.chunk();
            payload.extend_from_slice(chunk);
            let n = chunk.len();
            write_buf.advance(n);
        }

        let cmd = WriteCmd::Write {
            data: payload,
            fin: false,
        };

        if let Some(permit) = self.pending_permit.take() {
            // Infallible path: slot was pre-reserved by poll_ready.
            // Also clear any stale reservation future.
            self.reserve_fut = None;
            permit.send((self.inner.stream_id, cmd));
            Ok(())
        } else {
            // Safety fallback: caller violated the poll_ready-first contract.
            self.inner
                .conn_tx
                .try_send((self.inner.stream_id, cmd))
                .map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => {
                        StreamErrorIncoming::Unknown(Box::new(std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "OxiQUIC write channel full (poll_ready was not called)",
                        )))
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        StreamErrorIncoming::Unknown(Box::new(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "OxiQUIC driver task has been dropped",
                        )))
                    }
                })
        }
    }

    /// Signal end-of-stream (FIN) to the driver.
    ///
    /// This uses the same permit-reservation pattern as `poll_ready`/`send_data`
    /// to guarantee reliable delivery.  A previous `try_send` approach silently
    /// dropped the FIN when the write channel was full under load, causing the
    /// peer's `recv_data` loop to hang indefinitely waiting for stream end.
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        // Ensure an in-flight reservation future exists.
        if self.fin_reserve_fut.is_none() {
            self.fin_reserve_fut = Some(Box::pin(self.inner.conn_tx.clone().reserve_owned()));
        }

        let fut = self
            .fin_reserve_fut
            .as_mut()
            .expect("fin_reserve_fut was just set above if None");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                self.fin_reserve_fut = None;
                let cmd = WriteCmd::Write {
                    data: Vec::new(),
                    fin: true,
                };
                permit.send((self.inner.stream_id, cmd));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                self.fin_reserve_fut = None;
                // Driver is gone — the stream is already effectively closed,
                // so treat this as a successful finish.
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Send a QUIC RESET_STREAM frame to abruptly terminate this stream.
    fn reset(&mut self, reset_code: u64) {
        let cmd = WriteCmd::Reset {
            error_code: reset_code,
        };
        // Ignore send errors: if the driver is gone the stream is already gone.
        let _ = self.inner.conn_tx.try_send((self.inner.stream_id, cmd));
    }

    fn send_id(&self) -> H3StreamId {
        self.h3_id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// H3RecvStream
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a [`RecvStreamHandle`]'s data channel and implements
/// [`h3::quic::RecvStream`].
///
/// The `RecvStreamHandle` is consumed on construction; the inner
/// `mpsc::Receiver<Vec<u8>>` is accessed directly to satisfy h3's
/// `poll_data` interface (which returns whole `Bytes` chunks rather than
/// streaming bytes into a caller-supplied buffer). The write channel and
/// stream ID are also retained so that `stop_sending` can forward a
/// `STOP_SENDING` frame to the driver.
pub struct H3RecvStream {
    data_rx: mpsc::Receiver<Vec<u8>>,
    /// Write channel shared with the send side, for sending STOP_SENDING.
    conn_tx: crate::handle::WriteTx,
    /// The QUIC stream ID, kept for STOP_SENDING.
    stream_id: oxiquic_core::StreamId,
    h3_id: H3StreamId,
}

impl H3RecvStream {
    /// Consume a [`RecvStreamHandle`] and wrap it.
    ///
    /// # Errors
    ///
    /// Returns [`StreamErrorIncoming::Unknown`] if the underlying stream id
    /// exceeds the QUIC VarInt ceiling (2^62 − 1).
    pub fn new(
        inner: RecvStreamHandle,
        conn_tx: crate::handle::WriteTx,
    ) -> Result<Self, StreamErrorIncoming> {
        let stream_id = inner.stream_id();
        let h3_id = convert_stream_id(stream_id)?;
        Ok(Self {
            data_rx: inner.into_data_rx(),
            conn_tx,
            stream_id,
            h3_id,
        })
    }
}

impl RecvStream for H3RecvStream {
    /// The chunk type returned from `poll_data`.
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => Poll::Ready(Ok(Some(Bytes::from(data)))),
            Poll::Ready(None) => {
                // Channel closed — either the driver dropped or the stream
                // reached FIN. Signal orderly EOF to h3.
                Poll::Ready(Ok(None))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Send a QUIC STOP_SENDING frame to request the peer cease sending on
    /// this stream (RFC 9000 §19.5).
    fn stop_sending(&mut self, error_code: u64) {
        let cmd = WriteCmd::StopSending { error_code };
        // Ignore send errors: if the driver is gone the stream is already gone.
        let _ = self.conn_tx.try_send((self.stream_id, cmd));
    }

    fn recv_id(&self) -> H3StreamId {
        self.h3_id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// H3BidiStream
// ─────────────────────────────────────────────────────────────────────────────

/// A bidirectional QUIC stream adapter that implements [`h3::quic::BidiStream`],
/// [`h3::quic::SendStream`], and [`h3::quic::RecvStream`].
///
/// Constructed from a `(SendStreamHandle, RecvStreamHandle)` pair produced by
/// [`DrivenConnection::open_bidi_stream`][crate::endpoint::DrivenConnection::open_bidi_stream].
pub struct H3BidiStream {
    send: H3SendStream,
    recv: H3RecvStream,
}

impl H3BidiStream {
    /// Wrap a `(SendStreamHandle, RecvStreamHandle)` pair.
    ///
    /// # Errors
    ///
    /// Returns [`StreamErrorIncoming::Unknown`] if either stream id exceeds the
    /// QUIC VarInt ceiling (2^62 − 1).
    pub fn new(
        send: SendStreamHandle,
        recv: RecvStreamHandle,
    ) -> Result<Self, StreamErrorIncoming> {
        // Clone the write channel so the recv side can send STOP_SENDING.
        let conn_tx = send.conn_tx.clone();
        Ok(Self {
            send: H3SendStream::new(send)?,
            recv: H3RecvStream::new(recv, conn_tx)?,
        })
    }
}

// Delegate SendStream to inner H3SendStream.
impl<B: Buf> SendStream<B> for H3BidiStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        <H3SendStream as SendStream<B>>::poll_ready(&mut self.send, cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        <H3SendStream as SendStream<B>>::send_data(&mut self.send, data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        <H3SendStream as SendStream<B>>::poll_finish(&mut self.send, cx)
    }

    fn reset(&mut self, reset_code: u64) {
        <H3SendStream as SendStream<B>>::reset(&mut self.send, reset_code);
    }

    fn send_id(&self) -> H3StreamId {
        <H3SendStream as SendStream<B>>::send_id(&self.send)
    }
}

// Delegate RecvStream to inner H3RecvStream.
impl RecvStream for H3BidiStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> H3StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> BidiStream<B> for H3BidiStream {
    type SendStream = H3SendStream;
    type RecvStream = H3RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OxiQuicOpenStreams — implements h3::quic::OpenStreams
// ─────────────────────────────────────────────────────────────────────────────

type OpenBidiFut = Option<
    Pin<
        Box<dyn Future<Output = Result<(SendStreamHandle, RecvStreamHandle), OxiQuicError>> + Send>,
    >,
>;
type OpenSendFut =
    Option<Pin<Box<dyn Future<Output = Result<SendStreamHandle, OxiQuicError>> + Send>>>;

/// Adapts a [`DrivenConnection`] to the [`h3::quic::OpenStreams`] trait.
///
/// This type is returned by the `opener` method on [`OxiQuicH3Connection`]
/// (via the [`h3::quic::Connection`] trait) and allows the `h3` crate to open
/// new outgoing QUIC streams for control/QPACK channels.
pub struct OxiQuicOpenStreams {
    conn: DrivenConnection,
    /// Pending future for opening a bidirectional stream.
    pending_open_bidi: OpenBidiFut,
    /// Pending future for opening a unidirectional stream.
    pending_open_send: OpenSendFut,
}

impl OxiQuicOpenStreams {
    fn new(conn: DrivenConnection) -> Self {
        Self {
            conn,
            pending_open_bidi: None,
            pending_open_send: None,
        }
    }
}

impl<B: Buf> OpenStreams<B> for OxiQuicOpenStreams {
    type BidiStream = H3BidiStream;
    type SendStream = H3SendStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        // Start a new future if none is in flight.
        if self.pending_open_bidi.is_none() {
            let conn = self.conn.clone();
            self.pending_open_bidi = Some(Box::pin(async move { conn.open_bidi_stream().await }));
        }
        // Poll the pending future.
        let result = {
            let fut = self.pending_open_bidi.as_mut().expect("just set above");
            fut.as_mut().poll(cx)
        };
        match result {
            Poll::Ready(Ok((send, recv))) => {
                self.pending_open_bidi = None;
                match H3BidiStream::new(send, recv) {
                    Ok(bidi) => Poll::Ready(Ok(bidi)),
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Poll::Ready(Err(e)) => {
                self.pending_open_bidi = None;
                Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                    std::io::Error::other(format!("failed to open bidi stream: {e}")),
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        // Start a new future if none is in flight.
        if self.pending_open_send.is_none() {
            let conn = self.conn.clone();
            self.pending_open_send = Some(Box::pin(async move { conn.open_uni_stream().await }));
        }
        // Poll the pending future.
        let result = {
            let fut = self.pending_open_send.as_mut().expect("just set above");
            fut.as_mut().poll(cx)
        };
        match result {
            Poll::Ready(Ok(send)) => {
                self.pending_open_send = None;
                match H3SendStream::new(send) {
                    Ok(h3_send) => Poll::Ready(Ok(h3_send)),
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Poll::Ready(Err(e)) => {
                self.pending_open_send = None;
                Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                    std::io::Error::other(format!("failed to open uni stream: {e}")),
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        let conn = self.conn.clone();
        let reason = reason.to_vec();
        // Fire-and-forget close: spawn a task to send the close signal.
        tokio::spawn(async move {
            let _ = conn.close(code.value(), &reason).await;
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OxiQuicH3Connection — implements h3::quic::Connection
// ─────────────────────────────────────────────────────────────────────────────

type AcceptRecvFut =
    Option<Pin<Box<dyn Future<Output = Result<RecvStreamHandle, OxiQuicError>> + Send>>>;
type AcceptBidiFut = Option<
    Pin<
        Box<dyn Future<Output = Result<(SendStreamHandle, RecvStreamHandle), OxiQuicError>> + Send>,
    >,
>;

/// Adapts a [`DrivenConnection`] to the [`h3::quic::Connection`] trait,
/// enabling use with `h3::client::builder().build(conn)` and
/// `h3::server::builder().build(conn)`.
///
/// Construct via [`OxiQuicH3Connection::new`], then pass to the h3 builder.
pub struct OxiQuicH3Connection {
    conn: DrivenConnection,
    open_streams: OxiQuicOpenStreams,
    /// Write channel, cloned to attach to uni receive streams for STOP_SENDING.
    write_tx: crate::handle::WriteTx,
    /// Pending future for accepting a unidirectional stream.
    pending_accept_recv: AcceptRecvFut,
    /// Pending future for accepting a bidirectional stream.
    pending_accept_bidi: AcceptBidiFut,
}

impl OxiQuicH3Connection {
    /// Wrap a [`DrivenConnection`] in the h3 connection adapter.
    #[must_use]
    pub fn new(conn: DrivenConnection) -> Self {
        let write_tx = conn.write_tx();
        let open_streams = OxiQuicOpenStreams::new(conn.clone());
        Self {
            conn,
            open_streams,
            write_tx,
            pending_accept_recv: None,
            pending_accept_bidi: None,
        }
    }
}

// Delegate OpenStreams to the inner OxiQuicOpenStreams.
impl<B: Buf> OpenStreams<B> for OxiQuicH3Connection {
    type BidiStream = H3BidiStream;
    type SendStream = H3SendStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        <OxiQuicOpenStreams as OpenStreams<B>>::poll_open_bidi(&mut self.open_streams, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        <OxiQuicOpenStreams as OpenStreams<B>>::poll_open_send(&mut self.open_streams, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <OxiQuicOpenStreams as OpenStreams<B>>::close(&mut self.open_streams, code, reason);
    }
}

impl<B: Buf> h3::quic::Connection<B> for OxiQuicH3Connection {
    type RecvStream = H3RecvStream;
    type OpenStreams = OxiQuicOpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        // Start a new future if none is in flight.
        if self.pending_accept_recv.is_none() {
            let conn = self.conn.clone();
            self.pending_accept_recv =
                Some(Box::pin(async move { conn.accept_uni_stream().await }));
        }
        let result = {
            let fut = self.pending_accept_recv.as_mut().expect("just set above");
            fut.as_mut().poll(cx)
        };
        match result {
            Poll::Ready(Ok(recv)) => {
                self.pending_accept_recv = None;
                let write_tx = self.write_tx.clone();
                match H3RecvStream::new(recv, write_tx) {
                    Ok(h3_recv) => Poll::Ready(Ok(h3_recv)),
                    Err(e) => {
                        Poll::Ready(Err(ConnectionErrorIncoming::InternalError(e.to_string())))
                    }
                }
            }
            Poll::Ready(Err(_)) => {
                self.pending_accept_recv = None;
                // Connection closed: signal orderly EOF to h3.
                Poll::Ready(Err(ConnectionErrorIncoming::ApplicationClose {
                    error_code: 0x0100, // H3_NO_ERROR
                }))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        // Start a new future if none is in flight.
        if self.pending_accept_bidi.is_none() {
            let conn = self.conn.clone();
            self.pending_accept_bidi =
                Some(Box::pin(async move { conn.accept_bidi_stream().await }));
        }
        let result = {
            let fut = self.pending_accept_bidi.as_mut().expect("just set above");
            fut.as_mut().poll(cx)
        };
        match result {
            Poll::Ready(Ok((send, recv))) => {
                self.pending_accept_bidi = None;
                match H3BidiStream::new(send, recv) {
                    Ok(bidi) => Poll::Ready(Ok(bidi)),
                    Err(e) => {
                        Poll::Ready(Err(ConnectionErrorIncoming::InternalError(e.to_string())))
                    }
                }
            }
            Poll::Ready(Err(_)) => {
                self.pending_accept_bidi = None;
                Poll::Ready(Err(ConnectionErrorIncoming::ApplicationClose {
                    error_code: 0x0100, // H3_NO_ERROR
                }))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        OxiQuicOpenStreams::new(self.conn.clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use h3::proto::frame::Frame;
    use oxiquic_core::{Direction, Initiator, StreamId};
    use tokio::sync::mpsc;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build a `SendStreamHandle` with the given channel sender and stream index.
    fn make_send_handle(
        tx: mpsc::Sender<(StreamId, WriteCmd)>,
        stream_index: u64,
    ) -> SendStreamHandle {
        SendStreamHandle {
            stream_id: StreamId::new(Initiator::Client, Direction::Bidirectional, stream_index),
            conn_tx: tx,
        }
    }

    /// Call `poll_ready` through the `SendStream<Bytes>` trait impl.
    fn poll_ready_for_test(
        stream: &mut H3SendStream,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        <H3SendStream as SendStream<Bytes>>::poll_ready(stream, cx)
    }

    /// Call `send_data` through the trait with a `Frame<Bytes>::Data` payload.
    ///
    /// `Frame<Bytes>` satisfies `Into<WriteBuf<Bytes>>` per h3's stream module.
    fn send_frame(stream: &mut H3SendStream, payload: &[u8]) -> Result<(), StreamErrorIncoming> {
        let frame = Frame::<Bytes>::Data(Bytes::copy_from_slice(payload));
        <H3SendStream as SendStream<Bytes>>::send_data(stream, frame)
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    /// `poll_ready` returns `Ready(Ok(()))` immediately when the channel has
    /// capacity, and `send_data` consumes the permit without error.
    #[tokio::test]
    async fn poll_ready_immediate_when_capacity_available() {
        let (tx, mut rx) = mpsc::channel::<(StreamId, WriteCmd)>(4);
        let handle = make_send_handle(tx, 0);
        let mut stream = H3SendStream::new(handle).expect("valid stream id");

        // poll_ready must be Ready immediately when channel is not full.
        let result = std::future::poll_fn(|cx| poll_ready_for_test(&mut stream, cx)).await;
        assert!(result.is_ok(), "poll_ready failed: {result:?}");

        // send_data must succeed (permit consumed infallibly).
        send_frame(&mut stream, b"hello").expect("send_data failed after poll_ready");

        // Verify the message arrived as a Write command.
        let msg = rx.recv().await.expect("channel unexpectedly closed");
        assert!(
            matches!(msg.1, WriteCmd::Write { .. }),
            "expected WriteCmd::Write, got something else"
        );
    }

    /// Core waker-registration test: two streams share a capacity-1 channel.
    ///
    /// This test verifies that the `reserve_fut` is kept alive across `Pending`
    /// returns so tokio can re-wake the task when capacity is freed. The key
    /// assertion is that stream B completes its `poll_ready` after stream A's
    /// message is drained — which only works if B's waiter node stayed
    /// registered in the channel semaphore.
    ///
    /// A lost-wakeup implementation (re-creating `Box::pin(reserve_owned())`
    /// on every `Pending` return) would fail this test because the waiter node
    /// would be dropped and the task would never be re-polled.
    #[tokio::test]
    async fn backpressure_waker_registered_across_pending() {
        // Channel with capacity 1: A fills the only slot; B must wait.
        let (tx, mut rx) = mpsc::channel::<(StreamId, WriteCmd)>(1);

        // stream_index 0 → id 0, stream_index 1 → id 4.
        let handle_a = make_send_handle(tx.clone(), 0);
        let handle_b = make_send_handle(tx.clone(), 1);

        let mut stream_a = H3SendStream::new(handle_a).expect("valid stream id a");

        // ── Step 1: A reserves a permit and fills the only channel slot ───────
        std::future::poll_fn(|cx| poll_ready_for_test(&mut stream_a, cx))
            .await
            .expect("A poll_ready failed");
        send_frame(&mut stream_a, b"msg-a").expect("A send_data failed");

        // ── Step 2: Spawn B as a task so tokio manages its waker ──────────────
        // The task calls poll_ready in a loop until it becomes Ready, then
        // sends its message. It signals completion via a one-shot channel.
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut stream_b = H3SendStream::new(handle_b).expect("valid stream id b");
            // poll_fn drives poll_ready properly: returns when Ready.
            std::future::poll_fn(|cx| poll_ready_for_test(&mut stream_b, cx))
                .await
                .expect("B poll_ready failed");
            send_frame(&mut stream_b, b"msg-b").expect("B send_data failed");
            let _ = done_tx.send(());
        });

        // Yield once so the spawned task has a chance to run and block.
        tokio::task::yield_now().await;

        // ── Step 3: Drain the channel — this should wake stream B's task ──────
        let _msg_a = rx.recv().await.expect("expected msg-a");

        // ── Step 4: Wait for B to complete ────────────────────────────────────
        // done_rx completes only after B's poll_ready became Ready and it
        // sent its message. If B's waker was not registered the spawned task
        // would hang forever, and this would time out.
        tokio::time::timeout(std::time::Duration::from_secs(5), done_rx)
            .await
            .expect("stream B timed out — waker may not have been registered correctly")
            .expect("done_tx dropped without sending");

        // Confirm B's message is in the channel.
        let msg_b = rx.recv().await.expect("expected msg-b from stream B");
        assert!(
            matches!(msg_b.1, WriteCmd::Write { .. }),
            "expected WriteCmd::Write from B"
        );
    }

    /// Double-poll guard: calling `poll_ready` twice in succession when a permit
    /// is already held must return `Ready(Ok(()))` on the second call without
    /// reserving a new channel slot.
    #[tokio::test]
    async fn double_poll_ready_is_idempotent() {
        let (tx, _rx) = mpsc::channel::<(StreamId, WriteCmd)>(4);
        let handle = make_send_handle(tx, 0);
        let mut stream = H3SendStream::new(handle).expect("valid stream id");

        let r1 = std::future::poll_fn(|cx| poll_ready_for_test(&mut stream, cx)).await;
        assert!(r1.is_ok(), "first poll_ready failed");

        // Second poll_ready: permit already held, must return Ready immediately.
        let r2 = std::future::poll_fn(|cx| poll_ready_for_test(&mut stream, cx)).await;
        assert!(r2.is_ok(), "second poll_ready failed");
    }

    /// Channel-closed path: `poll_ready` must return an error when the receiver
    /// is dropped (simulating the driver task being gone).
    #[tokio::test]
    async fn poll_ready_returns_error_when_channel_closed() {
        let (tx, rx) = mpsc::channel::<(StreamId, WriteCmd)>(4);
        drop(rx); // simulate driver being dropped

        let handle = make_send_handle(tx, 0);
        let mut stream = H3SendStream::new(handle).expect("valid stream id");

        let result = std::future::poll_fn(|cx| poll_ready_for_test(&mut stream, cx)).await;
        assert!(
            result.is_err(),
            "expected Err when channel is closed, got Ok"
        );
    }
}
