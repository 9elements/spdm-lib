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

use crate::codec::{Codec, MessageBuf};
use crate::error::{CommandError, CommandResult};
use crate::protocol::{ReqRespCode, SpdmMsgHdr};

use crate::commands::error::{ErrorCode, ErrorResponse};

/// Decode an error response and return the contained [ErrorCode] and [ErrorData]
/// parsed into an [ErrorResponse].
///
/// # Warning
///
/// After this decoding, the message buffer will still contain the Extended Error Data.
/// Since it is currently not always necessary for the business logic to parse and
/// process it, it is left as is for now.
/// The function calling [decode_error_response] is responsible to retrieve the
/// extended error data from `resp_buf` if needed.
pub fn decode_error_response(resp_buf: &mut MessageBuf) -> CommandResult<ErrorResponse> {
    let spdm_hdr = match SpdmMsgHdr::decode(resp_buf) {
        Ok(hdr) => hdr,
        Err(e) => return Err((false, CommandError::Codec(e))),
    };

    match spdm_hdr.req_resp_code() {
        Ok(ReqRespCode::Error) => {}
        _ => return Err((false, CommandError::InvalidResponse)),
    }

    let error_resp = match ErrorResponse::decode(resp_buf) {
        Ok(r) => r,
        Err(e) => return Err((false, CommandError::Codec(e))),
    };

    let error_code = match ErrorCode::try_from(error_resp.error_code()) {
        Ok(code) => code,
        Err(_) => return Err((false, CommandError::InvalidResponse)),
    };

    Ok(ErrorResponse::new(error_code, error_resp.error_data()))
}
