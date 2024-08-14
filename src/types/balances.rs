use super::evm::{Address, EncodedMessage, SignedMessage};
use alloc::vec;
use alloc::vec::Vec;
use ethabi::{encode as abi_encode, Token};
use ink::primitives::AccountId;
use scale::{Decode, Encode};

pub type Balance = u128;

#[derive(Debug, Encode, Decode, Clone, scale_info::TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct Asset {
    id: u32,
    decimals: u8,
}

pub struct ProverRequest {
    substrate_account: AccountId,
    evm_address: Address,
    asset: Asset,
    amount: Balance,
}

impl ProverRequest {
    pub fn new(
        substrate_account: AccountId,
        evm_address: Address,
        asset: Asset,
        amount: Balance,
    ) -> Self {
        Self {
            substrate_account,
            evm_address,
            asset,
            amount,
        }
    }
}

impl Encode for ProverRequest {
    fn encode(&self) -> Vec<u8> {
        let account: &[u8; 32] = self.substrate_account.as_ref();

        let tokens = vec![
            // substrate account
            Token::Bytes(account.to_vec()),
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

#[derive(Debug, Encode, Decode, Clone, scale_info::TypeInfo)]
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
