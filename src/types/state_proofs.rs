use alloc::vec::Vec;
use scale::{Decode, Encode};
use sp_core::H256;

pub type StateRoot = H256;

#[derive(Debug, Encode, Decode, Clone)]
#[cfg_attr(
    feature = "std",
    derive(ink::storage::traits::StorageLayout, scale_info::TypeInfo)
)]
pub struct SnapshotCommitment {
    pub block_hash: Vec<u8>,
    pub state_root: Vec<u8>,
}

/// Proof holds the relevant proof data.
#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]

pub struct Proof {
    /// State height
    pub height: u64,
    /// Scale encoded proof
    pub proof: Vec<u8>,
}

/// Hashing algorithm for the state proof
#[derive(Debug, Encode, Decode, Clone)]
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
