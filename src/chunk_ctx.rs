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

use crate::commands::measurements::response::MeasurementsResponse;

#[derive(Debug, PartialEq)]
pub enum ChunkError {
    /// Super hacky way to signal back the client application via [CommandError::Chunk(ChunkError::None)]
    /// that the chunking process has started and that it now has to retrieve the chunked data.
    None,
    LargeResponseInitError,
    NoLargeResponseInProgress,
    InvalidChunkHandle,
    InvalidChunkSeqNum,
    InvalidMessageOffset,
}

/// Stores state and metadata for managing ongoing large message requests and responses.
#[derive(Default)]
struct ChunkInfo {
    chunk_in_use: bool,
    chunk_handle: u8,
    chunk_seq_num: u16,
    bytes_transferred: usize,
    large_msg_size: usize,
}

impl ChunkInfo {
    /// Reset the chunk info.
    ///
    /// # Arguments
    /// - `reset_handle`: If `reset_handle` is set, the handle of the chunk info
    ///   is set to `0`. If not, it is incremented to be ready for the next chunk operation.
    pub fn reset(&mut self, reset_handle: bool) {
        self.chunk_in_use = false;
        if reset_handle {
            self.chunk_handle = 0;
        } else {
            self.chunk_handle = self.chunk_handle.wrapping_add(1);
        }
        self.chunk_seq_num = 0;
        self.bytes_transferred = 0;
    }

    pub fn init(&mut self, large_msg_size: usize, handle: Option<u8>) -> u8 {
        self.chunk_in_use = true;
        self.chunk_seq_num = 0;
        self.bytes_transferred = 0;
        self.large_msg_size = large_msg_size;
        if let Some(h) = handle {
            self.chunk_handle = h;
        }
        self.chunk_handle
    }
}

pub type ChunkResult<T> = Result<T, ChunkError>;

/// Represents a large message response type that can be split into chunks
pub(crate) enum LargeResponse {
    Measurements(MeasurementsResponse),
}

/// Manages the context for ongoing large message responses.
/// The naming might be confusion, but we re-use this struct for both requester and responder.
///
/// # Requester
///
/// For the requester, this [LargeResponseCtx] is used to track the state
/// of `CHUNK_SEND` commands.
///
/// # Responder
///
/// For the responder, this [LargeResponseCtx] is used to track the state
/// of `CHUNK_RESPONSE` commands.
#[derive(Default)]
pub(crate) struct LargeResponseCtx {
    chunk_info: ChunkInfo,
    response: Option<LargeResponse>,
}

impl LargeResponseCtx {
    /// Reset the context to its initial state
    /// This action increments the chunk handle
    pub(crate) fn reset(&mut self) {
        self.chunk_info.reset(false);
        self.response = None;
    }

    /// Initialize the context for a large response
    ///
    /// # Arguments
    /// * `large_rsp` - The large message response to be sent
    /// * `large_rsp_size` - The size of the response message
    ///
    /// # Returns
    /// A `ChunkResult` containing the chunk handle(u8) if successful
    pub fn init(&mut self, large_rsp: LargeResponse, large_rsp_size: usize) -> u8 {
        self.response = Some(large_rsp);
        self.chunk_info.init(large_rsp_size, None)
    }

    /// Is large message response in progress
    ///
    /// # Returns
    /// Returns `true` if a large response is currently in progress, otherwise `false`
    pub fn in_progress(&self) -> bool {
        self.chunk_info.chunk_in_use
    }

    pub fn valid(&self, handle: u8, chunk_seq_num: u16) -> bool {
        self.chunk_info.chunk_in_use
            && self.chunk_info.chunk_handle == handle
            && self.chunk_info.chunk_seq_num == chunk_seq_num
    }

    pub fn large_response_size(&self) -> usize {
        self.chunk_info.large_msg_size
    }

    pub fn last_chunk(&self, chunk_size: usize) -> (bool, usize) {
        if !self.chunk_info.chunk_in_use {
            return (false, 0);
        }
        let rem_len = self.chunk_info.large_msg_size - self.chunk_info.bytes_transferred;

        // Check if the last chunk is reached and
        (rem_len <= chunk_size, rem_len)
    }

    pub fn response(&self) -> Option<&LargeResponse> {
        self.response.as_ref()
    }

    pub fn bytes_transferred(&self) -> usize {
        self.chunk_info.bytes_transferred
    }

    pub fn seq_no(&self) -> u16 {
        self.chunk_info.chunk_seq_num
    }

    pub fn handle(&self) -> u8 {
        self.chunk_info.chunk_handle
    }
}

/// Manages the context for ongoing large message retrievals on the **requester** side.
///
/// Initialized when the requester receives `ERROR(LargeResponse)` and tracks
/// progress across successive `CHUNK_GET` / `CHUNK_RESPONSE` exchanges until
/// the last chunk has been received.
#[derive(Default)]
pub(crate) struct LargeRequestCtx {
    chunk_info: ChunkInfo,
}

impl LargeRequestCtx {
    /// Initialize context for a new large response retrieval.
    ///
    /// Call this when `ERROR(LargeResponse)` is received.
    ///
    /// # Arguments
    /// * `handle` - The handle value carried in `Param2` of the `ERROR` message.
    pub(crate) fn init(&mut self, handle: u8) {
        // Total size is unknown until the first CHUNK_RESPONSE arrives.
        self.chunk_info.init(0, Some(handle));
    }

    /// Discard any in-progress retrieval and reset to the initial state.
    pub(crate) fn reset(&mut self) {
        self.chunk_info.reset(true);
    }

    /// Returns `true` if a large response retrieval is currently in progress.
    pub(crate) fn in_progress(&self) -> bool {
        self.chunk_info.chunk_in_use
    }

    /// Returns the handle identifying the current large response transfer.
    pub(crate) fn handle(&self) -> u8 {
        self.chunk_info.chunk_handle
    }

    /// Returns the `ChunkSeqNo` that shall appear in the next `CHUNK_GET`.
    pub(crate) fn current_seq_num(&self) -> u16 {
        self.chunk_info.chunk_seq_num
    }

    /// Returns the number of bytes successfully received so far.
    pub(crate) fn bytes_received(&self) -> usize {
        self.chunk_info.bytes_transferred
    }

    /// Returns the total size of the large response.
    ///
    /// Only meaningful after the first `CHUNK_RESPONSE` (`ChunkSeqNo == 0`)
    /// has been processed and [`set_total_size`] has been called.
    pub(crate) fn total_size(&self) -> usize {
        self.chunk_info.large_msg_size
    }

    /// Record the total response size decoded from the first `CHUNK_RESPONSE`.
    pub(crate) fn set_total_size(&mut self, size: usize) {
        self.chunk_info.large_msg_size = size;
    }

    /// Advance tracking state after a chunk has been successfully received.
    ///
    /// Adds `chunk_size` to `bytes_received` and bumps the sequence number so
    /// that the next `CHUNK_GET` requests the following chunk.
    pub(crate) fn advance(&mut self, chunk_size: usize) {
        self.chunk_info.bytes_transferred += chunk_size;
        self.chunk_info.chunk_seq_num = self.chunk_info.chunk_seq_num.wrapping_add(1);
    }
}
