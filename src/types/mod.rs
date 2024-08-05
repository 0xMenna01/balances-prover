use scale::{Decode, Encode};
use scale_info::TypeInfo;

mod access_control;
mod crypto;
mod evm;

pub use access_control::{AccessControl, SudoAccount};
pub use crypto::{ContractKeyPair, ContractSeed, };

#[derive(Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum Error {
    // A caller account has a bad origin
    BadOrigin,
    // Invalid length for the seed of the secret
    InvalidSeedLength,
}

pub type Result<T> = core::result::Result<T, Error>;
