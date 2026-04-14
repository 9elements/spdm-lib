// Licensed under the Apache-2.0 license
use crate::codec::CommonCodec;
use crate::context::SpdmContext;
use crate::protocol::*;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// The maximum number of chunks that can be transferred for a large response.
/// This is determined by the size of the chunk sequence number field (u16) in the
/// `ChunkGetReq` and `ChunkResponseFixed` messages.
pub const MAX_NUM_CHUNKS: u16 = u16::MAX;

pub mod request;
pub mod response;

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct ChunkGet {
    /// Reserved.
    param1: u8,

    /// Shall contain a handle. This field shall be the same value as given in the
    /// `Handle` field of the `ERROR` message of `ErrorCode=LargeResponse`.
    ///
    /// # Note
    ///
    /// The fields name in spec is `Param2`.
    handle: u8,

    /// Shall indicate the desired chunk sequence number of the Large SPDM Response
    /// to retrieve.
    chunk_seq_no: u16,
}
impl CommonCodec for ChunkGet {}

impl ChunkGet {}
#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
/// The fixed fields of the `CHUNK_RESPONSE` message. The actual response payload
/// follows these fixed fields in the message.
///
/// - `LargeResponseSize`: Field is only present in the first chunk (i.e., when `ChunkSeqNo` is 0).
/// - `SPDMchunk`: The chunk of the large response message. The size of this field is determined by the
struct ChunkResponseFixed {
    /// # Note
    ///
    /// The fields name in spec is `Param1`.
    chunk_sender_attr: ChunkSenderAttr,

    /// # Note
    ///
    /// The fields name in spec is `Param2`.
    handle: u8,

    chunk_seq_no: u16,
    reserved: u16,
    chunk_size: u32,
}
impl CommonCodec for ChunkResponseFixed {}

impl ChunkResponseFixed {
    // Computes the chunk size based on the context and the chunk sequence number
    // Returns the chunk size and a boolean indicating if this is the last chunk
    pub(crate) fn compute_chunk_size(ctx: &SpdmContext, chunk_seq_num: u16) -> (usize, bool) {
        let extra_field_size = if chunk_seq_num == 0 {
            size_of::<LargeResponseSize>()
        } else {
            0
        };
        let chunk_size = ctx
            .min_data_transfer_size()
            .saturating_sub(size_of::<SpdmMsgHdr>() + size_of::<Self>() + extra_field_size);

        let (is_last_chunk, remaining_len) = ctx.large_resp_context.last_chunk(chunk_size);

        if is_last_chunk {
            (remaining_len, true)
        } else {
            (chunk_size, false)
        }
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct ChunkSenderAttr(u8);
    impl Debug;
    u8;
    /// If set, the chunk indicated by `ChunkSeqNo` shall represent the last chunk
    /// of the large SPDM message.
    pub last_chunk, set_last_chunk: 0, 0;
    reserved, _: 7, 1;
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct ChunkReceiverAttr(u8);
    impl Debug;
    u8;
    /// If set, the receiver of a large SPDM request message detected an error in
    /// the Request before the last chunk was received. If set, the sender of the
    /// large SPDM request message shall terminate the transfer of any remaining chunks.
    /// After addressing the issue, the sender of the failed large SPDM request
    /// message can transfer the fixed large SPDM request message as a new transfer.
    pub early_error_detected, set_early_error_detected: 0, 0;
    reserved, _: 7, 1;
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct LargeResponseSize(u32);
impl CommonCodec for LargeResponseSize {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
/// The fixed size components of the `CHUNK_SEND` request.
/// When sent, this struct is followed by
/// - `LargeMessageSize` field (only present in the first chunk, i.e., when `ChunkSeqNo` is 0). See [LargeMessageSize].
pub(crate) struct ChunkSendFixed {
    param1: ChunkSenderAttr,

    /// # Note
    ///
    /// The fields name in spec is `Param2`.
    handle: u8,

    /// Shall identify the chunk sequence number associated with SPDMchunk .
    chunk_seq_no: u32,

    chunk_size: u32,
}

impl ChunkSendFixed {
    pub fn new(handle: u8, chunk_seq_no: u32, chunk_size: u32, last_chunk: bool) -> Self {
        let mut sender_attr = ChunkSenderAttr(0);
        sender_attr.set_last_chunk(last_chunk as u8);
        Self {
            param1: sender_attr,
            handle,
            chunk_seq_no,
            chunk_size,
        }
    }

    // Computes the chunk size based on the context and the chunk sequence number
    // Returns the chunk size and a boolean indicating if this is the last chunk
    pub(crate) fn compute_chunk_size(ctx: &SpdmContext, chunk_seq_num: u16) -> (usize, bool) {
        let extra_field_size = if chunk_seq_num == 0 {
            size_of::<LargeMessageSize>()
        } else {
            0
        };
        let chunk_size = ctx
            .min_data_transfer_size()
            .saturating_sub(size_of::<SpdmMsgHdr>() + size_of::<Self>() + extra_field_size);

        let (is_last_chunk, remaining_len) = ctx.large_resp_context.last_chunk(chunk_size);

        if is_last_chunk {
            (remaining_len, true)
        } else {
            (chunk_size, false)
        }
    }
}

impl CommonCodec for ChunkSendFixed {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
/// Size of the large SPDM message being transferred. This field shall only be present when ChunkSeqNo is zero and shall have a non-zero value. Shall be greater  than the DataTransferSize of the receiving SPDM endpoint.
struct LargeMessageSize(u32);
impl CommonCodec for LargeMessageSize {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
/// # Note
/// This struct may be followed by the variable length field `ResponseToLargeRequest`.
/// `ResponseToLargeRequest` shall be present on the last chunk (that is, when LastChunk is set),
/// or when the `EarlyErrorDetected` bit in Param1 is set.
///
/// This field shall contain the response to the large SPDM request message.
/// When the `EarlyErrorDetected` bit in Param1 is set, this field shall contain an ERROR message.
pub(crate) struct ChunkSendAck {
    param1: ChunkReceiverAttr,
    /// # Note
    ///
    /// The fields name in spec is `Param2`.
    handle: u8,
    chunk_seq_no: u32,
}

/// Maximal size of the large response that can be transferred in chunks.
/// If a large response exceeds this size, it cannot be transferred in chunks and
/// the requester should not send a CHUNK_GET request for it.
pub(crate) fn max_chunked_resp_size(ctx: &SpdmContext) -> usize {
    let min_data_transfer_size = ctx.min_data_transfer_size();
    let fixed_chunk_resp_size = size_of::<SpdmMsgHdr>() + size_of::<ChunkResponseFixed>();

    // compute max possible response size that can be transferred in chunks is less than the large response size
    (min_data_transfer_size).saturating_sub(fixed_chunk_resp_size) * MAX_NUM_CHUNKS as usize
        - size_of::<u32>()
}
