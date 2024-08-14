use crate::types::{Error, Result};
use alloc::format;
use alloc::{string::String, vec, vec::Vec};
use hex::FromHex;
use pink_extension as pink;

pub fn call_rpc(rpc_node: &String, data: Vec<u8>) -> Result<Vec<u8>> {
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

pub fn extract_hex_from(hex_string: &str) -> Result<Vec<u8>> {
    if !hex_string.starts_with("0x") {
        return Err(Error::InvalidHexData);
    }
    if hex_string.len() <= 2 {
        return Err(Error::HexStringOutOfBounds);
    }

    let hex_string = &hex_string[2..];
    Ok(Vec::from_hex(hex_string).map_err(|_| Error::InvalidHexData)?)
}

pub fn encode_to_hex(value: &[u8]) -> String {
    hex::encode(value)
}
