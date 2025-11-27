// Licensed under the Apache-2.0 license

use crate::error::{SpdmError, SpdmResult};

const MAX_NUM_SUPPORTED_SPDM_VERSIONS: usize = 4;
const MAX_SUPPORTED_VERSION: SpdmVersion = SpdmVersion::V14;

/// Representation of all supported SPDM versions.
///
/// For a full list, see [DSP0274](https://www.dmtf.org/dsp/dsp0274).
#[derive(Debug, Default, PartialEq, Clone, Copy, PartialOrd)]
pub enum SpdmVersion {
    #[default]
    V10,
    V11,
    V12,
    V13,
    V14,
}

impl SpdmVersion {
    pub fn to_str(&self) -> &'static str {
        match self {
            SpdmVersion::V10 => "1.0.*",
            SpdmVersion::V11 => "1.1.*",
            SpdmVersion::V12 => "1.2.*",
            SpdmVersion::V13 => "1.3.*",
            SpdmVersion::V14 => "1.4.*",
        }
    }
}

impl TryFrom<u8> for SpdmVersion {
    type Error = SpdmError;
    fn try_from(value: u8) -> Result<Self, SpdmError> {
        match value {
            0x10 => Ok(SpdmVersion::V10),
            0x11 => Ok(SpdmVersion::V11),
            0x12 => Ok(SpdmVersion::V12),
            0x13 => Ok(SpdmVersion::V13),
            0x14 => Ok(SpdmVersion::V14),
            _ => Err(SpdmError::UnsupportedVersion),
        }
    }
}

impl From<SpdmVersion> for u8 {
    fn from(version: SpdmVersion) -> Self {
        version.to_u8()
    }
}

impl SpdmVersion {
    fn to_u8(self) -> u8 {
        match self {
            SpdmVersion::V10 => 0x10,
            SpdmVersion::V11 => 0x11,
            SpdmVersion::V12 => 0x12,
            SpdmVersion::V13 => 0x13,
            SpdmVersion::V14 => 0x14,
        }
    }

    pub fn major(&self) -> u8 {
        self.to_u8() >> 4
    }

    pub fn minor(&self) -> u8 {
        self.to_u8() & 0x0F
    }

    /// Check if `self` is compatible with `other`.
    /// For now, we compare the version numbers directly.
    /// If `other` is newer than our version, we consider them incompatible.
    ///
    /// ```rust
    /// use spdm_lib::protocol::version::SpdmVersion;
    ///
    /// assert!(SpdmVersion::V14.is_compatible(&SpdmVersion::V10));
    /// assert!(!SpdmVersion::V12.is_compatible(&SpdmVersion::V13));
    /// ```
    pub fn is_compatible(&self, other: &SpdmVersion) -> bool {
        self.to_u8() >= other.to_u8()
    }
}

pub(crate) fn validate_supported_versions(supported_versions: &[SpdmVersion]) -> SpdmResult<()> {
    if supported_versions.is_empty()
        || supported_versions.len() > MAX_NUM_SUPPORTED_SPDM_VERSIONS
        || supported_versions
            .iter()
            .any(|v| *v > MAX_SUPPORTED_VERSION)
    {
        Err(SpdmError::InvalidParam)?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_validate_supported_versions() {
        let supported_versions: [SpdmVersion; 4] = [
            SpdmVersion::V10,
            SpdmVersion::V11,
            SpdmVersion::V12,
            SpdmVersion::V13,
        ];
        assert_eq!(
            validate_supported_versions(&supported_versions).unwrap(),
            ()
        );
    }
}
