use crate::types::{
    balances::{BalanceProverMessage, ProverRequest},
    crypto::{
        ecdsa::ContractKeyPair,
        hasher::{ContractBlake2_128Concat, ContractTwox64Concat, StorageHasher},
    },
    evm::{EncodedMessage, SignedMessage},
};
use alloc::vec::Vec;
use scale::Encode;

pub type BalancesStorageKey = Vec<u8>;

pub struct BalanceStorageKeyBuilder {
    pub prefix: Vec<u8>,
    pub suffix: Vec<Vec<u8>>,
}

/// A storage item key within its hashing algorithm
pub enum StorageItemKey<T> {
    Blake2_128Concat(T),
    Twox64Concat(T),
}

impl BalanceStorageKeyBuilder {
    pub fn from_prefix(prefix: &[u8]) -> Self {
        Self {
            prefix: prefix.to_vec(),
            suffix: Vec::new(),
        }
    }

    pub fn push_item_key<T: Encode>(self, key: StorageItemKey<T>) -> Self {
        let mut suffix = self.suffix;
        match key {
            StorageItemKey::Blake2_128Concat(key) => {
                suffix.push(ContractBlake2_128Concat::hash(&key.encode()))
            }
            StorageItemKey::Twox64Concat(key) => {
                suffix.push(ContractTwox64Concat::hash(&key.encode()))
            }
        };

        Self {
            prefix: self.prefix,
            suffix,
        }
    }

    pub fn build(self) -> BalancesStorageKey {
        let mut key = Vec::new();

        let suffix = self.suffix.concat();

        key.extend_from_slice(&self.prefix);
        key.extend_from_slice(&suffix);

        key
    }
}

#[derive(Default)]
pub struct EmptyMessage;

#[derive(Default)]
pub struct BalanceProverMessageBuilder<T>(T);

impl BalanceProverMessageBuilder<EmptyMessage> {
    pub fn request(self, request: ProverRequest) -> BalanceProverMessageBuilder<EncodedMessage> {
        BalanceProverMessageBuilder(request.encode())
    }
}

impl BalanceProverMessageBuilder<EncodedMessage> {
    pub fn sign_request(
        self,
        pair: &ContractKeyPair,
    ) -> BalanceProverMessageBuilder<SignedMessage> {
        BalanceProverMessageBuilder(SignedMessage {
            signature: pair.sign(&self.0),
            encoded_msg: self.0,
        })
    }
}

impl BalanceProverMessageBuilder<SignedMessage> {
    pub fn build(self) -> BalanceProverMessage {
        self.0.into()
    }
}
