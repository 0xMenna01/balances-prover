use super::crypto::{ecdsa::Signature, hasher::ContractKeccak256};
use alloc::vec::Vec;
use ethabi::{ethereum_types::H160, Address as EvmAddress};
use k256::ecdsa::VerifyingKey;
use scale::{Decode, Encode};
use sp_core::Hasher;

pub type EncodedMessage = Vec<u8>;

pub trait ABIEncode {
    fn abi_encode(&self) -> EncodedMessage;
}

/// An EVM address
#[derive(Debug, Encode, Decode, Clone, Copy, scale_info::TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct Address([u8; 20]);

impl From<Address> for EvmAddress {
    fn from(address: Address) -> EvmAddress {
        H160(address.0)
    }
}

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

pub struct SignedMessage {
    pub signature: Signature,
    pub encoded_msg: EncodedMessage,
}
