use alloc::vec::Vec;

pub type BalancesStorageKey = Vec<u8>;

#[derive(Default)]
pub struct BalanceStorageKeyBuilder {
    pub prefix: Vec<u8>,
    pub suffix: Vec<Vec<u8>>,
}

impl BalanceStorageKeyBuilder {
    pub fn prefix(self, prefix: &[u8]) -> Self {
        Self {
            prefix: prefix.to_vec(),
            suffix: Vec::new(),
        }
    }

    pub fn add_storage_item(self, item: &[u8]) -> Self {
        let mut suffix = self.suffix;
        suffix.push(item.to_vec());
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
