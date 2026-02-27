// Licensed under the Apache-2.0 license
use crate::codec::{Codec, MessageBuf};
use crate::commands::chunk::{ChunkGet, ChunkResponseFixed, ChunkSendFixed, LargeResponseSize};
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::state::ConnectionState;

/// Build and encode a `CHUNK_GET` request into `req_buf`.
///
/// The handle and chunk sequence number are read from
/// `ctx.large_req_context`, which must already be initialised (i.e.
/// [`LargeRequestCtx::init`] was called after receiving
/// `ERROR(LargeResponse)`).
///
/// For a detailed flow diagram, see DSP0274, v1.0.4, Figure 25.
pub(crate) fn generate_chunk_get_request<'a>(
    ctx: &mut SpdmContext<'a>,
    req_buf: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let spdm_hdr = SpdmMsgHdr::new(
        ctx.state.connection_info.version_number(),
        ReqRespCode::ChunkGet,
    );

    let mut payload_len = spdm_hdr
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let chunk_get = ChunkGet {
        param1: 0,
        handle: ctx.large_req_context.handle(),
        chunk_seq_no: ctx.large_req_context.current_seq_num(),
    };
    payload_len += chunk_get
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    req_buf
        .push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    Ok(())
}

/// Decode and validate one `CHUNK_RESPONSE` message, copying its payload
/// slice into `output` at the correct byte offset.
///
/// # Returns
/// * `Ok(true)`  – this was the last chunk; the caller should read
///   `ctx.large_req_context.bytes_received()` and then reset the context.
/// * `Ok(false)` – more chunks are still expected.
///
/// # Errors
/// Returns an error if the version, handle, or sequence number is wrong, if
/// the output buffer is too small, or if decoding fails.
pub(crate) fn handle_chunk_response<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: &SpdmMsgHdr,
    resp: &mut MessageBuf<'a>,
    output: &mut MessageBuf<'a>,
) -> CommandResult<bool> {
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        return Err((false, CommandError::InvalidResponse));
    }

    check_chunk_get_preconditions(ctx)?;

    let chunk_fixed =
        ChunkResponseFixed::decode(resp).map_err(|e| (false, CommandError::Codec(e)))?;

    // Validate handle and sequence number against our tracked state.
    if chunk_fixed.handle != ctx.large_req_context.handle()
        || chunk_fixed.chunk_seq_no != ctx.large_req_context.current_seq_num()
    {
        return Err((false, CommandError::InvalidChunkContext));
    }

    // The first chunk (ChunkSeqNo == 0) carries the total large response size.
    if chunk_fixed.chunk_seq_no == 0 {
        let large_rsp_size =
            LargeResponseSize::decode(resp).map_err(|e| (false, CommandError::Codec(e)))?;
        ctx.large_req_context
            .set_total_size(large_rsp_size.0 as usize);

        // Sanity: caller's buffer must be large enough for the whole response.
        if ctx.large_req_context.total_size() > output.capacity() {
            return Err((false, CommandError::BufferTooSmall));
        }
    }

    let chunk_size = chunk_fixed.chunk_size as usize;
    if resp.data_len() < chunk_size {
        return Err((false, CommandError::InvalidResponse));
    }

    // Extend the output tail to make room for this chunk, then copy the
    // payload into the newly reserved range at the correct byte offset.
    let offset = ctx.large_req_context.bytes_received();
    output
        .put_data(chunk_size)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    let chunk_data = resp
        .data(chunk_size)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    output
        .data_mut(offset + chunk_size)
        .map_err(|e| (false, CommandError::Codec(e)))?[offset..]
        .copy_from_slice(chunk_data);
    resp.pull_data(chunk_size)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Advance sequence number and byte count for the next iteration.
    ctx.large_req_context.advance(chunk_size);

    Ok(chunk_fixed.chunk_sender_attr.last_chunk() == 1)
}

/// Validate that preconditions for issuing a `CHUNK_GET` are met.
///
/// Returns an `UnexpectedRequest` error (suitable for propagating back to the
/// caller) if:
/// - capabilities have not yet been negotiated, or
/// - chunking capability is not advertised, or
/// - no large response retrieval is currently in progress.
pub(crate) fn check_chunk_get_preconditions(ctx: &SpdmContext) -> CommandResult<()> {
    if ctx.state.connection_info.state() < ConnectionState::AfterCapabilities
        || ctx.local_capabilities.flags.chunk_cap() == 0
        || !ctx.large_req_context.in_progress()
    {
        Err((false, CommandError::UnsupportedRequest))?;
    }
    Ok(())
}

/// Generate a `CHUNK_SEND` request based on a large message that should be sent.
/// Per function call, the appropriate amount of chunk data is consumed from the `data` buffer
/// and the resulting packet is written into `req_buf` buffer.
///
/// Thereby, `data` must contain the entire SPDM message, including header.
///
/// # Note
/// Before this function ca be called, the `large_resp_context` has to be reset.
/// Since we are sending the chunks instead of receiving, we use the `large_resp_context` struct.
pub(crate) fn generate_chunk_send_request<'a>(
    ctx: &mut SpdmContext<'a>,
    data: &mut MessageBuf<'a>,
    req_buf: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    check_chunk_get_preconditions(ctx)?;

    let spdm_hdr = SpdmMsgHdr::new(
        ctx.state.connection_info.version_number(),
        ReqRespCode::ChunkResponse,
    );
    spdm_hdr
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let (chunk_size, last) = ChunkSendFixed::compute_chunk_size(ctx, 0);

    let chunk_send_fixed = ChunkSendFixed::new(
        ctx.large_resp_context.handle(),
        ctx.large_resp_context.seq_no() as u32,
        chunk_size as u32,
        last,
    );

    chunk_send_fixed
        .encode(req_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    // Write chunk_size many bytes of the data buffer into the req_buf.

    Ok(())
}
