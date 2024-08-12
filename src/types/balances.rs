use super::crypto::hasher::{ContractBlake2_128Concat, ContractTwox64Concat, StorageHasher};
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
