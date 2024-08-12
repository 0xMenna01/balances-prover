use alloc::vec::Vec;
use ink::env::hash::{Blake2x128, Blake2x256, CryptoHash, Keccak256};
use scale::MaxEncodedLen;
use sp_core::Hasher;

pub trait StorageHasher {
    fn hash(x: &[u8]) -> Vec<u8>;
    fn max_len<K: MaxEncodedLen>() -> usize;
}

#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ContractBlake2_128Concat;

impl StorageHasher for ContractBlake2_128Concat {
    fn hash(x: &[u8]) -> Vec<u8> {
        let mut x_hash = [0u8; 16];
        Blake2x128::hash(x, &mut x_hash);
        x_hash.iter().chain(x.iter()).cloned().collect::<Vec<_>>()
    }

    fn max_len<K: MaxEncodedLen>() -> usize {
        K::max_encoded_len().saturating_add(16)
    }
}

#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ContractTwox64Concat;

impl StorageHasher for ContractTwox64Concat {
    fn hash(x: &[u8]) -> Vec<u8> {
        sp_core::hashing::twox_64(x)
            .iter()
            .chain(x.iter())
            .cloned()
            .collect::<Vec<_>>()
    }

    fn max_len<K: MaxEncodedLen>() -> usize {
        K::max_encoded_len().saturating_add(8)
    }
}

#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ContractKeccak256;

impl Hasher for ContractKeccak256 {
    type Out = sp_core::H256;
    type StdHasher = hash256_std_hasher::Hash256StdHasher;
    const LENGTH: usize = 32;

    fn hash(s: &[u8]) -> Self::Out {
        let mut output = [0_u8; Self::LENGTH];
        Keccak256::hash(s, &mut output);
        output.into()
    }
}

#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ContractBlakeTwo256;

impl Hasher for ContractBlakeTwo256 {
    type Out = sp_core::H256;
    type StdHasher = hash256_std_hasher::Hash256StdHasher;
    const LENGTH: usize = 32;

    fn hash(s: &[u8]) -> Self::Out {
        let mut output = [0_u8; Self::LENGTH];
        Blake2x256::hash(s, &mut output);
        output.into()
    }
}
