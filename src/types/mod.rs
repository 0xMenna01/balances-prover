use alloc::{string::String, vec::Vec};
use scale::{Decode, Encode};

pub mod access_control;
pub mod balances;
pub mod crypto;
pub mod evm;
pub mod rpc;

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
    /// Balance request message has already been signed by the contract
    RequestAlreadySigned,
    /// Invalid H256
    InvalidHashBytes,
    /// Invalid account balance
    InvalidBalance,
    /// Balance decoding error
    InvalidBalanceDecoding,
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Encode, Decode, Clone)]
#[cfg_attr(
    feature = "std",
    derive(ink::storage::traits::StorageLayout, scale_info::TypeInfo)
)]
pub struct SnapshotCommitment {
    pub height: u32,
    pub block_hash: Vec<u8>,
    pub state_root: Vec<u8>,
    pub hasher: HashAlgorithm,
}

/// Hashing algorithm for the state proof
#[derive(Debug, Encode, Decode, Clone)]
#[cfg_attr(
    feature = "std",
    derive(ink::storage::traits::StorageLayout, scale_info::TypeInfo)
)]
pub enum HashAlgorithm {
    /// For chains that use keccak as their hashing algo
    Keccak,
    /// For chains that use blake2 as their hashing algo
    Blake2,
}

/// Holds the relevant data needed for state proof verification
#[derive(Debug, Encode, Decode, Clone)]
pub struct SubstrateStateProof {
    /// Algorithm to use for state proof verification
    pub hasher: HashAlgorithm,
    /// Storage proof for the parachain headers
    pub storage_proof: Vec<Vec<u8>>,
}

#[derive(Debug, Encode, Decode, Clone, Copy, scale_info::TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub enum ProverStatus {
    Paused,
    Live,
}
