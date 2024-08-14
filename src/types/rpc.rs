use alloc::vec::Vec;
use scale::Encode;
use serde::Deserialize;

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct ReadProof<'a> {
    pub jsonrpc: &'a str,
    #[serde(borrow)]
    pub result: ReadProofAtBlock<'a>,
    pub id: u32,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
#[serde(bound(deserialize = "Vec<&'a str>: Deserialize<'de>"))]
pub struct ReadProofAtBlock<'a> {
    pub at: &'a str,
    #[serde(borrow)]
    pub proof: Vec<&'a str>,
}
