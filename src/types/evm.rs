use k256::ecdsa::VerifyingKey;
use scale::{Decode, Encode};
use sp_core::Hasher;

use super::crypto::hasher::ContractKeccak256;

/// An EVM address
#[derive(Debug, Encode, Decode, Clone, Copy, scale_info::TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct Address([u8; 20]);

impl From<VerifyingKey> for Address {
    fn from(value: VerifyingKey) -> Self {
        // EVM address
        let mut address = [0u8; 20];

        let public = value.to_encoded_point(false);
        let public = &public.as_bytes()[1..];

        let hashed_public = ContractKeccak256::hash(public);

        address.copy_from_slice(&hashed_public.as_bytes()[12..]);

        Self(address)
    }
}
