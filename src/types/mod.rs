use alloc::string::String;
use scale::{Decode, Encode};

pub mod access_control;
pub mod balances;
pub mod crypto;
pub mod evm;
pub mod rpc;
pub mod state_proofs;

#[derive(Debug, PartialEq, Eq, Encode, Decode, scale_info::TypeInfo)]
pub enum Error {
    // A caller account has a bad origin
    BadOrigin,
    // Invalid length for the seed of the secret
    InvalidSeedLength,
    /// Error reading state proof
    KeyError(String),
    /// Failed to decode storage proof
    DecodingProofError(String),
    /// Invalid RPC request body,
    RpcInvalidBody,
    /// Invalid hex
    InvalidHexData,
    /// Hex string out of bounds error
    HexStringOutOfBounds,
    /// Error in RPC request
    RpcRequestFailed,
}

pub type Result<T> = core::result::Result<T, Error>;
