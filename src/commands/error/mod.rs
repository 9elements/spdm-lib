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

use crate::codec::CommonCodec;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub mod request;
pub mod response;

pub(crate) use response::*;

// SPDM error codes
/// See Table 65 — Error code and error data
#[derive(Debug, PartialEq, Clone, Copy, Immutable, IntoBytes)]
#[repr(u8)]
pub enum ErrorCode {
    InvalidRequest = 0x01,
    Busy = 0x03,
    UnexpectedRequest = 0x04,
    Unspecified = 0x05,
    DecryptError = 0x06,
    UnsupportedRequest = 0x07,
    RequestInFlight = 0x08,
    InvalidResponseCode = 0x09,
    SessionLimitExceeded = 0x0A,
    SessionRequired = 0x0B,
    ResetRequired = 0x0C,
    ResponseTooLarge = 0x0D,
    RequestTooLarge = 0x0E,
    LargeResponse = 0x0F,
    MessageLost = 0x10,
    InvalidPolicy = 0x11,
    DataTooLarge = 0x12,
    VersionMismatch = 0x41,
    ResponseNotReady = 0x42,
    RequestResynch = 0x43,
    OperationFailed = 0x44,
    NoPendingRequests = 0x45,
    VendorDefined = 0xFF,
}

impl From<ErrorCode> for u8 {
    fn from(code: ErrorCode) -> Self {
        code as u8
    }
}

impl TryFrom<u8> for ErrorCode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(ErrorCode::InvalidRequest),
            0x03 => Ok(ErrorCode::Busy),
            0x04 => Ok(ErrorCode::UnexpectedRequest),
            0x05 => Ok(ErrorCode::Unspecified),
            0x06 => Ok(ErrorCode::DecryptError),
            0x07 => Ok(ErrorCode::UnsupportedRequest),
            0x08 => Ok(ErrorCode::RequestInFlight),
            0x09 => Ok(ErrorCode::InvalidResponseCode),
            0x0A => Ok(ErrorCode::SessionLimitExceeded),
            0x0B => Ok(ErrorCode::SessionRequired),
            0x0C => Ok(ErrorCode::ResetRequired),
            0x0D => Ok(ErrorCode::ResponseTooLarge),
            0x0E => Ok(ErrorCode::RequestTooLarge),
            0x0F => Ok(ErrorCode::LargeResponse),
            0x10 => Ok(ErrorCode::MessageLost),
            0x11 => Ok(ErrorCode::InvalidPolicy),
            0x12 => Ok(ErrorCode::DataTooLarge),
            0x41 => Ok(ErrorCode::VersionMismatch),
            0x42 => Ok(ErrorCode::ResponseNotReady),
            0x43 => Ok(ErrorCode::RequestResynch),
            0x44 => Ok(ErrorCode::OperationFailed),
            0x45 => Ok(ErrorCode::NoPendingRequests),
            0xFF => Ok(ErrorCode::VendorDefined),
            _ => Err(()),
        }
    }
}

pub type ErrorData = u8;
pub type LargeResponseHandle = u8;
/// Per spec definition (TODO: since when?) this error response may be followed
/// by the field `ExtendedErrorData`, which might be up to 32 bytes large.
/// As of version 1.4, the `ExtendedErrorData` may be available for the following Error Codes:
/// - [ErrorCode::ResponseTooLarge] --> [ResponseTooLargeData]
/// - [ErrorCode::LargeResponse] --> [LargeResponseData]
/// - [ErrorCode::DataTooLarge] --> [DataTooLargeData]
/// - [ErrorCode::ResponseNotReady] --> [ResponseNotReadyData]
/// - [ErrorCode::VendorDefined] --> TODO, variable length.
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct ErrorResponse {
    /// param1
    error_code: u8,
    /// param2
    error_data: ErrorData,
}

impl ErrorResponse {
    pub fn new(error_code: ErrorCode, error_data: ErrorData) -> Self {
        Self {
            error_code: error_code.into(),
            error_data,
        }
    }

    pub fn error_code(&self) -> u8 {
        self.error_code
    }

    pub fn error_data(&self) -> u8 {
        self.error_data
    }
}

impl CommonCodec for ErrorResponse {}

#[derive(FromBytes, IntoBytes, Immutable, Debug)]
#[repr(C)]
pub struct ResponseNotReadyData {
    /// Shall be the exponent expressed in logarithmic (base-2 scale) to calculate
    /// RDT time in µs after which the Responder can provide successful completion response.
    rdt_exponent: u8,
    /// Shall be the request code that triggered this response.
    request_code: u8,
    /// Shall be the opaque handle that the Requester shall pass in with the RESPOND_IF_READY
    /// request message.
    token: u8,
    /// Shall be the multiplier used to compute WT Max in µs to indicate that the
    /// response might be dropped after this delay.
    rdtm: u8,
}

impl ResponseNotReadyData {
    pub fn rdt_exponent(&self) -> u8 {
        self.rdt_exponent
    }

    pub fn request_code(&self) -> u8 {
        self.request_code
    }

    pub fn token(&self) -> u8 {
        self.token
    }

    pub fn rdtm(&self) -> u8 {
        self.rdtm
    }
}

impl CommonCodec for ResponseNotReadyData {}

#[derive(FromBytes, IntoBytes, Immutable, Debug)]
#[repr(C)]
pub struct LargeResponseData {
    ///Shall be a unique value that identifies the Large SPDM Response and shall
    /// be the same value for all chunks of the same large SPDM message.
    handle: LargeResponseHandle,
}

impl LargeResponseData {
    /// Return the Large Response Handle.
    pub fn handle(&self) -> LargeResponseHandle {
        self.handle
    }
}

impl CommonCodec for LargeResponseData {}

#[derive(FromBytes, IntoBytes, Immutable, Debug)]
#[repr(C)]
pub struct ResponseTooLargeData {
    /// Shall be the size of the actual response.
    actual_size: u32,
}

impl ResponseTooLargeData {
    /// Return the actual size.
    pub fn actual_size(&self) -> u32 {
        self.actual_size
    }
}

impl CommonCodec for ResponseTooLargeData {}

type DataTooLargeData = ResponseTooLargeData;
