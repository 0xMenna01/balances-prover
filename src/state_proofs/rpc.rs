use crate::types::{rpc::ReadProof, Error, Result};
use crate::utils;
use alloc::{format, string::String, vec::Vec};

/// The RPC that handles read proofs requests
#[derive(Debug)]
#[ink::storage_item]
pub struct Rpc {
    pub url: String,
}

impl Rpc {
    pub fn new(url: String) -> Self {
        Self { url }
    }

    pub fn get_read_proof(&self, secure_storage_key: &[u8], at: &[u8]) -> Result<Vec<Vec<u8>>> {
        let storage_key = format!("0x{}", utils::rpc::encode_to_hex(secure_storage_key));
        let at = format!("0x{}", utils::rpc::encode_to_hex(at));

        let data = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"state_getReadProof","params":[["{}"], "{}"]}}"#,
            storage_key, at
        )
        .into_bytes();

        let resp_body = utils::rpc::call_rpc(&self.url, data)?;
        let (response_proof, _): (ReadProof, usize) =
            serde_json_core::from_slice(&resp_body).or(Err(Error::RpcInvalidBody))?;

        // construct the proof
        let mut proof = Vec::new();
        for hex_str in response_proof.result.proof.into_iter() {
            let trie_node_hash = utils::rpc::extract_hex_from(&hex_str)?;
            proof.push(trie_node_hash);
        }

        Ok(proof)
    }
}
