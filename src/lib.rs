#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

mod state_proofs;
mod types;
mod utils;

// pink_extension is short for Phala ink! extension
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod balances_prover {

    use super::pink;
    use crate::{
        state_proofs::rpc::Rpc,
        types::{
            access_control::{AccessControl, SudoAccount},
            balances::Asset,
            crypto::ecdsa::{ContractKeyPair, ContractSeed},
            evm::Address,
            state_proofs::SnapshotCommitment,
            Error, Result,
        },
    };
    use alloc::{string::String, vec::Vec};
    use ink::storage::Lazy;
    use pink::PinkEnvironment;

    /// Defines the storage of your contract.
    /// All the fields will be encrypted and stored on-chain.
    /// In this stateless example, we just add a useless field for demo.
    #[ink(storage)]
    pub struct BalancesProver {
        /// The contract sudo account
        sudo: SudoAccount,
        /// The EVM address of the contract that proves balances
        evm_address: Address,
        /// The seed of the contract for the EVM address
        seed: Lazy<ContractSeed>,
        /// The chain snapshot commitment
        snapshot: SnapshotCommitment,
        /// The balances storage key prefix,
        storage_key_prefix: Vec<u8>,
        /// The asset for which the balance needs to be checked
        asset: Asset,
        /// The RPC that handles the read requests of state proofs
        rpc: Rpc,
    }

    impl BalancesProver {
        /// Constructor to initializes your contract
        /// `state_root` is the state root of the block of which you want to take the snapshot for balances
        ///
        #[ink(constructor)]
        pub fn new(
            snapshot: SnapshotCommitment,
            storage_key_prefix: Vec<u8>,
            asset: Asset,
            http_endpoint: String,
        ) -> Self {
            let sudo = pink::env().caller();

            let pair = ContractKeyPair::generate(&snapshot.block_hash);
            let public = pair.public();

            let mut seed = Lazy::new();
            seed.set(&pair.into());

            Self {
                sudo,
                evm_address: public.into(),
                seed,
                snapshot,
                storage_key_prefix,
                asset,
                rpc: Rpc::new(http_endpoint),
            }
        }

        // Ensures the caller account has sudo permissions
        fn ensure_root(&self) -> Result<SudoAccount> {
            let who = self.env().caller();
            AccessControl::from_account(self.sudo).ensure_root(who)?;

            Ok(who)
        }

        // Obtains the contract secred seed
        fn seed(&self) -> Option<ContractSeed> {
            self.seed.get()
        }

        // Sets the contract seed used for the ECDSA signature
        fn set_seed(&mut self, seed: ContractSeed) {
            self.seed.set(&seed);
        }

        // Sets the EVM address of the contract that is associated to the seed
        fn set_address(&mut self, address: Address) {
            self.evm_address = address;
        }

        /// The EVM address of the contract used to sign messages
        #[ink(message)]
        pub fn get_address(&self) -> Address {
            self.evm_address
        }

        /// The contract sudo account
        #[ink(message)]
        pub fn get_sudo(&self) -> SudoAccount {
            self.sudo
        }

        /// Derives a new contract seed and changes the associated EVM address
        #[ink(message)]
        pub fn derive_new_key(&mut self) -> Result<()> {
            self.ensure_root()?;

            let contract_seed = self
                .seed()
                .expect("The seed is set during contract initialization");

            // Derive the new contract keypair
            let pair =
                ContractKeyPair::from_versioned_seed(&contract_seed.seed, contract_seed.version)
                    .expect("Seed is 32 bytes")
                    .derive_new_version();
            let public = pair.public();
            // Change the seed and the evm address
            self.set_seed(pair.into());
            self.set_address(public.into());

            Ok(())
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
