use scale::{Decode, Encode};
use scale_info::TypeInfo;

pub mod access_control;
pub mod balances;
pub mod crypto;
pub mod evm;
pub mod state_proofs;

#[derive(Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum Error {
    // A caller account has a bad origin
    BadOrigin,
    // Invalid length for the seed of the secret
    InvalidSeedLength,
}

pub type Result<T> = core::result::Result<T, Error>;
