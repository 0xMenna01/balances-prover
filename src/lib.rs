#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

mod types;

// pink_extension is short for Phala ink! extension
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod balances_prover {
    use crate::types::{AccessControl, ContractKeyPair, ContractSeed, Result, SudoAccount};

    use super::pink;
    use alloc::string::String;
    use hex_literal::hex;
    use pink::PinkEnvironment;

    use scale::{Decode, Encode};
    use scale_info::TypeInfo;

    /// Defines the storage of your contract.
    /// All the fields will be encrypted and stored on-chain.
    /// In this stateless example, we just add a useless field for demo.
    #[ink(storage)]
    pub struct BalancesProver {
        sudo: SudoAccount,
        seed: ContractSeed,
    }

    impl BalancesProver {
        /// Constructor to initializes your contract
        #[ink(constructor)]
        pub fn new() -> Self {
            let sudo = pink::env().caller();

            // TODO: input the correct state_commitmenti here or in the constructor
            let state_commitment =
                hex!("a5a5378cbadf4f19522a1859de4137904cacd0b485cd58d0c7a55cf892bc1874");

            Self {
                sudo,
                seed: ContractKeyPair::generate(&state_commitment).into(),
            }
        }

        fn ensure_root(&self, who: AccountId) -> Result<()> {
            AccessControl::from_account(self.sudo).ensure_root(who)
        }

        /// A function to handle direct off-chain Query from users.
        /// Such functions use the immutable reference `&self`
        /// so WILL NOT change the contract state.
        #[ink(message)]
        pub fn get_balance(&self) -> Result<String> {
            Ok(String::from("No Balance"))
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {}
    }
}
