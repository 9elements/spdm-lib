// Copyright 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use crate::chunk_ctx::ChunkError;
use crate::chunk_ctx::LargeResponse;
use crate::codec::{Codec, MessageBuf};
use crate::commands::chunk::{
    max_chunked_resp_size, ChunkGet, ChunkResponseFixed, ChunkSenderAttr, LargeResponseSize,
};
use crate::commands::error::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::state::ConnectionState;

fn process_chunk_get<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<(u8, u16)> {
    // Check that the spdm version valid and is >= SPDM_VERSION_1_2
    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }
    if connection_version < SpdmVersion::V12 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    let chunk_get_req = ChunkGet::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    if !ctx
        .large_resp_context
        .valid(chunk_get_req.handle, chunk_get_req.chunk_seq_no)
    {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    // compute max possible response size that can be transferred in chunks is less than the large response size
    let max_large_rsp_size = max_chunked_resp_size(ctx);

    if ctx.large_resp_context.large_response_size() > max_large_rsp_size {
        Err(ctx.generate_error_response(req_payload, ErrorCode::ResponseTooLarge, 0, None))?;
    }

    Ok((chunk_get_req.handle, chunk_get_req.chunk_seq_no))
}

fn encode_chunk_resp_fixed_fields(
    last_chunk: bool,
    handle: u8,
    chunk_seq_num: u16,
    chunk_size: usize,
    rsp: &mut MessageBuf,
) -> CommandResult<usize> {
    let chunk_sender_attr = if last_chunk {
        ChunkSenderAttr(1) // Set last_chunk bit
    } else {
        ChunkSenderAttr(0) // Clear last_chunk bit
    };

    // Prepare the fixed part of the chunk response
    let chunk_response_fixed = ChunkResponseFixed {
        chunk_sender_attr,
        handle,
        chunk_seq_no: chunk_seq_num,
        reserved: 0,
        chunk_size: chunk_size as u32,
    };

    // Encode the fixed part into the response buffer
    chunk_response_fixed
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))
}

fn encode_chunk_data(
    ctx: &mut SpdmContext<'_>,
    chunk_size: usize,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<usize> {
    // Get the chunk data from the large response context
    let offset = ctx.large_resp_context.bytes_transferred();
    rsp.put_data(chunk_size)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let chunk_buf = rsp
        .data_mut(chunk_size)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    if let Some(response) = ctx.large_resp_context.response() {
        match response {
            LargeResponse::Measurements(meas_rsp) => {
                // Get the chunk data from the measurements response
                meas_rsp.get_chunk(
                    ctx.hash,
                    ctx.rng,
                    ctx.evidence,
                    &mut ctx.measurements,
                    &mut ctx.transcript_mgr,
                    ctx.device_certs_store,
                    offset,
                    chunk_buf,
                )?;
            }
        }
    } else {
        Err((
            false,
            CommandError::Chunk(ChunkError::NoLargeResponseInProgress),
        ))?;
    }
    Ok(chunk_size)
}

fn generate_chunk_response<'a>(
    ctx: &mut SpdmContext<'a>,
    handle: u8,
    chunk_seq_num: u16,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Prepare the response
    // Spdm Header first
    let spdm_hdr = SpdmMsgHdr::new(
        ctx.state.connection_info.version_number(),
        ReqRespCode::ChunkResponse,
    );
    let mut payload_len = spdm_hdr
        .encode(rsp)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let (chunk_size, last_chunk) = ChunkResponseFixed::compute_chunk_size(ctx, chunk_seq_num);
    if chunk_size > ctx.large_resp_context.large_response_size() {
        Err((false, CommandError::InvalidChunkContext))?;
    }
    // Encode fixed fields of the chunk response
    payload_len +=
        encode_chunk_resp_fixed_fields(last_chunk, handle, chunk_seq_num, chunk_size, rsp)?;

    if chunk_seq_num == 0 {
        // If this is the first chunk, we need to encapsulate the large response size
        let large_response_size =
            LargeResponseSize(ctx.large_resp_context.large_response_size() as u32);
        payload_len += large_response_size
            .encode(rsp)
            .map_err(|e| (false, CommandError::Codec(e)))?;
    }

    // Encode chunk data of chunk size
    payload_len += encode_chunk_data(ctx, chunk_size, rsp)?;

    rsp.push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))
}

/// From the SPDM0274 Spec:
///
/// > To ensure the general interoperability and reliability of this transfer mechanism,
/// > these messages shall be prohibited from being transferred in chunks using this
/// > transfer mechanism:
///
/// - `GET_VERSION`
/// - `VERSION`
/// - `GET_CAPABILITIES`
/// - `CAPABILITIES` with `Param1` in the `GET_CAPABILITIES` request set to `0`.
/// - `ERROR`
pub(crate) fn handle_chunk_get<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let mut error_code = None;

    // Perform all checks and send a error response if any fail
    // 1. Check CHUNK_GET is sent after CAPABILITIES
    // 2. Check if chunk capabilities are enabled
    // 3. Check if a large response is in progress
    if ctx.state.connection_info.state() < ConnectionState::AfterCapabilities
        || ctx.local_capabilities.flags.chunk_cap() == 0
        || ctx.large_resp_context.in_progress()
    {
        error_code = Some(ErrorCode::UnexpectedRequest);
    }

    if let Some(code) = error_code {
        Err(ctx.generate_error_response(req_payload, code, 0, None))?;
    }

    // process CHUNK_GET request
    let (handle, chunk_seq_num) = process_chunk_get(ctx, spdm_hdr, req_payload)?;

    // Generate CHUNK_RESPONSE response
    ctx.prepare_response_buffer(req_payload)?;
    generate_chunk_response(ctx, handle, chunk_seq_num, req_payload)?;

    Ok(())
}
