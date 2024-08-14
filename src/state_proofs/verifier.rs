use crate::types::state_proofs::{HashAlgorithm, Proof, StateRoot, SubstrateStateProof};

use crate::types::{Error, Result};
use alloc::{collections::BTreeMap, format, vec::Vec};
use scale::Decode;
use sp_core::{Hasher, H256};
use sp_trie::{LayoutV0, StorageProof, Trie, TrieDBBuilder};

pub struct StateVerifier {
    keys: Vec<Vec<u8>>,
    root: StateRoot,
    proof: Proof,
}

impl StateVerifier {
    pub fn new(keys: &[Vec<u8>], root: &StateRoot, proof: &Proof) -> Self {
        StateVerifier {
            keys: keys.to_vec(),
            root: root.clone(),
            proof: proof.clone(),
        }
    }

    pub fn keys(&self) -> &[Vec<u8>] {
        &self.keys
    }

    pub fn state_root(&self) -> &StateRoot {
        &self.root
    }

    pub fn verify_state_proof<Keccak: Hasher<Out = H256>, Blake2: Hasher<Out = H256>>(
        &self,
    ) -> Result<BTreeMap<Vec<u8>, Option<Vec<u8>>>> {
        let state_proof: SubstrateStateProof = Decode::decode(&mut &*self.proof.proof)
            .map_err(|e| Error::DecodingProofError(format!("failed to decode proof: {e:?}")))?;

        let data = match state_proof.hasher {
            HashAlgorithm::Keccak => {
                let db = StorageProof::new(state_proof.storage_proof).into_memory_db::<Keccak>();
                let trie = TrieDBBuilder::<LayoutV0<Keccak>>::new(&db, &self.root).build();

                self.keys
                    .clone()
                    .into_iter()
                    .map(|key| {
                        let value = trie.get(&key).map_err(|e| {
                            Error::KeyError(format!("Error reading state proof: {e:?}"))
                        })?;
                        Ok((key, value))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?
            }
            HashAlgorithm::Blake2 => {
                let db = StorageProof::new(state_proof.storage_proof).into_memory_db::<Blake2>();
                let trie = TrieDBBuilder::<LayoutV0<Blake2>>::new(&db, &self.root).build();

                self.keys
                    .clone()
                    .into_iter()
                    .map(|key| {
                        let value = trie.get(&key).map_err(|e| {
                            Error::KeyError(format!("Error reading state proof: {e:?}"))
                        })?;
                        Ok((key, value))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?
            }
        };

        Ok(data)
    }
}
