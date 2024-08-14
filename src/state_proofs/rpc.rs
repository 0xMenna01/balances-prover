use crate::types::{
    rpc::{ReadProof, StorageProofParams},
    Error, Result,
};
use alloc::{format, string::String, vec, vec::Vec};
use hex::FromHex;
use pink_extension as pink;

/// The RPC that handles read proofs requests
#[derive(Debug)]
#[ink::storage_item]
pub struct Rpc {
    url: String,
}

impl Rpc {
    pub fn new(url: String) -> Self {
        Self { url }
    }

    pub fn get_read_proof(
        &self,
        secure_storage_key: &[u8],
        at: &String,
    ) -> Result<StorageProofParams> {
        let storage_key = format!("0x{}", encode_to_hex(secure_storage_key));
        let data = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"state_getReadProof","params":[["{}"], "{}"]}}"#,
            storage_key, at
        )
        .into_bytes();

        let resp_body = call_rpc(&self.url, data)?;
        let (response_proof, _): (ReadProof, usize) =
            serde_json_core::from_slice(&resp_body).or(Err(Error::RpcInvalidBody))?;

        // construct the substrate storage keys with the only necessary key
        let keys = vec![secure_storage_key.to_vec()];
        // construct the proof
        let mut proof = Vec::new();
        for hex_str in response_proof.result.proof.into_iter() {
            let trie_node_hash = extract_hex_from(&hex_str)?;
            proof.push(trie_node_hash);
        }

        Ok(StorageProofParams { proof, keys })
    }
}

fn call_rpc(rpc_node: &String, data: Vec<u8>) -> Result<Vec<u8>> {
    let content_length = format!("{}", data.len());
    let headers: Vec<(String, String)> = vec![
        ("Content-Type".into(), "application/json".into()),
        ("Content-Length".into(), content_length),
    ];

    let response = pink::http_post!(rpc_node, data, headers);
    if response.status_code != 200 {
        return Err(Error::RpcRequestFailed);
    }

    let body = response.body;
    Ok(body)
}

fn extract_hex_from(hex_string: &str) -> Result<Vec<u8>> {
    if !hex_string.starts_with("0x") {
        return Err(Error::InvalidHexData);
    }
    if hex_string.len() <= 2 {
        return Err(Error::HexStringOutOfBounds);
    }

    let hex_string = &hex_string[2..];
    Ok(Vec::from_hex(hex_string).map_err(|_| Error::InvalidHexData)?)
}

fn encode_to_hex(value: &[u8]) -> String {
    hex::encode(value)
}
