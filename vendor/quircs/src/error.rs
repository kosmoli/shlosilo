// shlosilo vendor patch (2026-09-17): thiserror removed for no_std; the
// error types keep their Display strings and implement core::error::Error.
use core::fmt;

#[derive(Debug)]
pub enum DecodeError {
    InvalidGridSize,
    InvalidVersion,
    DataEcc,
    FormatEcc,
    UnkownDataType,
    DataOverflow,
    DataUnderflow,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DecodeError::InvalidGridSize => "Invalid grid size",
            DecodeError::InvalidVersion => "Invalid version",
            DecodeError::DataEcc => "Format data ECC failure",
            DecodeError::FormatEcc => "ECC failure",
            DecodeError::UnkownDataType => "Unknown data type",
            DecodeError::DataOverflow => "Data overflow",
            DecodeError::DataUnderflow => "Data underflow",
        })
    }
}

impl core::error::Error for DecodeError {}

#[derive(Debug)]
pub enum ExtractError {
    OutOfBounds,
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Out of bounds")
    }
}

impl core::error::Error for ExtractError {}
