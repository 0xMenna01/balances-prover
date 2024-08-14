use super::{
    crypto::{
        ecdsa::ContractKeyPair,
        hasher::{ContractBlake2_128Concat, ContractTwox64Concat, StorageHasher},
    },
    evm::{ABIEncode, Address, EncodedMessage, SignedMessage},
};
use crate::types::{Error, Result};
use alloc::vec;
use alloc::vec::Vec;
use ethabi::{encode as abi_encode, Token};
use scale::{Decode, Encode};

pub type Balance = u128;

#[derive(Debug, Encode, Decode, Clone, scale_info::TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct Asset {
    id: u32,
    decimals: u8,
}

pub struct BalanceRequest {
    evm_address: Address,
    asset: Asset,
    amount: Balance,
}

impl BalanceRequest {
    pub fn new(evm_address: Address, asset: Asset, amount: Balance) -> Self {
        Self {
            evm_address,
            asset,
            amount,
        }
    }
}

impl Encode for BalanceRequest {
    fn encode(&self) -> Vec<u8> {
        let tokens = vec![
            // address
            Token::Address(self.evm_address.into()),
            // asset
            Token::Tuple(vec![
                // asset id
                Token::Uint(self.asset.id.into()),
                // asset decimals
                Token::Uint(self.asset.decimals.into()),
            ]),
            // balance amount
            Token::Uint(self.amount.into()),
        ];

        abi_encode(&tokens)
    }
}

pub struct BalanceProverMessage {
    pub encoded_request: EncodedMessage,
    pub signature: Vec<u8>,
}

impl From<SignedMessage> for BalanceProverMessage {
    fn from(signed_msg: SignedMessage) -> Self {
        Self {
            encoded_request: signed_msg.encoded_msg,
            signature: signed_msg.signature.to_vec(),
        }
    }
}
