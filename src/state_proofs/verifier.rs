use crate::types::crypto::hasher::{ContractBlakeTwo256, ContractKeccak256};
use crate::types::{HashAlgorithm, SubstrateStateProof};

use crate::types::{Error, Result};
use alloc::{format, vec::Vec};
use sp_core::H256;
use sp_trie::{LayoutV0, StorageProof, Trie, TrieDBBuilder};

pub fn verify_state_proof(
    root: &[u8],
    key: &[u8],
    state_proof: SubstrateStateProof,
) -> Result<Option<Vec<u8>>> {
    let root = h256_from_slice(root)?;

    let data = match state_proof.hasher {
        HashAlgorithm::Keccak => {
            let db =
                StorageProof::new(state_proof.storage_proof).into_memory_db::<ContractKeccak256>();
            let trie = TrieDBBuilder::<LayoutV0<ContractKeccak256>>::new(&db, &root).build();

            let value = trie
                .get(key)
                .map_err(|e| Error::KeyError(format!("Error reading state proof: {e:?}")))?;
            value
        }
        HashAlgorithm::Blake2 => {
            let db = StorageProof::new(state_proof.storage_proof)
                .into_memory_db::<ContractBlakeTwo256>();
            let trie = TrieDBBuilder::<LayoutV0<ContractBlakeTwo256>>::new(&db, &root).build();

            let value = trie
                .get(key)
                .map_err(|e| Error::KeyError(format!("Error reading state proof: {e:?}")))?;
            value
        }
    };

    Ok(data)
}

fn h256_from_slice(maybe_h256: &[u8]) -> Result<H256> {
    // Ensure the vector has exactly 32 bytes
    if maybe_h256.len() == 32 {
        let mut x = [0u8; 32];
        x.copy_from_slice(&maybe_h256);
        Ok(H256::from(x))
    } else {
        Err(Error::InvalidHashBytes)
    }
}
