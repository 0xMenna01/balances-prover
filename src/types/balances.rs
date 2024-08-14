use super::{
    crypto::hasher::{ContractBlake2_128Concat, ContractTwox64Concat, StorageHasher},
    evm::Address,
};
use alloc::vec::Vec;
use scale::{Decode, Encode};

pub type BalancesStorageKey = Vec<u8>;

pub type Balance = u128;

#[derive(Debug, Encode, Decode, Clone, scale_info::TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct Token {
    pub id: u32,
    pub decimals: u8,
}

pub struct BalanceRequestBuilder {
    evm_address: Address,
    token: Token,
    amount: Balance,
}

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

    pub fn push_item_key<T: Encode>(&mut self, key: StorageItemKey<T>) {
        match key {
            StorageItemKey::Blake2_128Concat(key) => self
                .suffix
                .push(ContractBlake2_128Concat::hash(&key.encode())),
            StorageItemKey::Twox64Concat(key) => {
                self.suffix.push(ContractTwox64Concat::hash(&key.encode()))
            }
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
