use ink::env::hash::{CryptoHash, Keccak256};
use k256::ecdsa::VerifyingKey;
use scale::{Decode, Encode};
use scale_info::TypeInfo;

/// An EVM address
#[derive(Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct Address([u8; 20]);

impl From<VerifyingKey> for Address {
    fn from(value: VerifyingKey) -> Self {
        // EVM address
        let mut address = [0u8; 20];

        let public = value.to_encoded_point(false);
        let public = &public.as_bytes()[1..];

        let hashed_public = &mut [0u8; 32];
        Keccak256::hash(public, hashed_public);

        address.copy_from_slice(&hashed_public[12..]);

        Self(address)
    }
}
