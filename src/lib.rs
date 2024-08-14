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
        state_proofs::{rpc::Rpc, verifier},
        types::{
            access_control::{AccessControl, SudoAccount},
            balances::{Asset, BalanceProverMessage, ProverRequest},
            crypto::ecdsa::{ContractKeyPair, ContractSeed},
            evm::Address,
            Error, ProverStatus, Result, SnapshotCommitment, SubstrateStateProof,
        },
        utils::balances::{BalanceProverMessageBuilder, BalanceStorageKeyBuilder, StorageItemKey},
    };
    use alloc::{string::String, vec::Vec};
    use ink::storage::Lazy;
    use pink::PinkEnvironment;
    use scale::Decode;

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
        /// The status of the prover contract
        status: ProverStatus,
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
            status: ProverStatus,
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
                status,
            }
        }

        // Ensures the caller account has sudo permissions
        fn ensure_root(&self) -> Result<SudoAccount> {
            let who = self.env().caller();
            AccessControl::from_account(self.sudo).ensure_root(who)?;

            Ok(who)
        }

        // Obtains the contract keypair
        fn pair(&self) -> ContractKeyPair {
            self.seed
                .get()
                .expect("The seed is set during contract initialization")
                .into()
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
        pub fn address(&self) -> Address {
            self.evm_address
        }

        /// The contract sudo account
        #[ink(message)]
        pub fn sudo(&self) -> SudoAccount {
            self.sudo
        }

        /// The rpc url
        #[ink(message)]
        pub fn rpc_url(&self) -> String {
            self.rpc.url.clone()
        }

        /// Derives a new contract seed and changes the associated EVM address
        #[ink(message)]
        pub fn force_derive_new_key(&mut self) -> Result<()> {
            self.ensure_root()?;

            // Derive the new contract keypair
            let pair = self.pair().derive_new_version();
            let public = pair.public();
            // Change the seed and the evm address
            self.set_seed(pair.into());
            self.set_address(public.into());

            Ok(())
        }

        /// Updates the snapshot
        #[ink(message)]
        pub fn force_update_snapshot(&mut self, snapshot: SnapshotCommitment) -> Result<()> {
            self.ensure_root()?;

            self.snapshot = snapshot;
            Ok(())
        }

        /// Updates the storage key prefix of the balances storage
        #[ink(message)]
        pub fn force_update_storage_key_prefix(&mut self, key_prefix: Vec<u8>) -> Result<()> {
            self.ensure_root()?;

            self.storage_key_prefix = key_prefix;
            Ok(())
        }

        #[ink(message)]
        pub fn force_update_asset_info(&mut self, asset_info: Asset) -> Result<()> {
            self.ensure_root()?;

            self.asset = asset_info;
            Ok(())
        }

        /// Updates the rpc url
        #[ink(message)]
        pub fn force_update_rpc_url(&mut self, url: String) -> Result<()> {
            self.ensure_root()?;

            self.rpc = Rpc::new(url);
            Ok(())
        }

        /// Updates the prover status
        #[ink(message)]
        pub fn force_update_prover_status(&mut self, status: ProverStatus) -> Result<()> {
            self.ensure_root()?;

            self.status = status;
            Ok(())
        }

        /// Proves the balance of the caller account on the chain at the state identified by the stored `snapshot`
        #[ink(message)]
        pub fn prove_balance(&self, claim_address: Address) -> Result<BalanceProverMessage> {
            let who = self.env().caller();
            // Construct the storage key to retrieve the caller balance amount
            let storage_key = BalanceStorageKeyBuilder::from_prefix(&self.storage_key_prefix)
                .push_item_key(StorageItemKey::Blake2_128Concat(who))
                .build();

            // Retrieve the substrate state proof via RPC
            let proof = SubstrateStateProof {
                hasher: self.snapshot.hasher.clone(),
                storage_proof: self
                    .rpc
                    .get_read_proof(&storage_key, &self.snapshot.block_hash)?,
            };

            // Verify the state proof and read the value
            let value =
                verifier::verify_state_proof(&self.snapshot.state_root, &storage_key, proof)?
                    .ok_or(Error::InvalidBalance)?;
            let amount: Balance =
                Decode::decode(&mut &*value).map_err(|_| Error::InvalidBalanceDecoding)?;

            // Return the prover message
            let request = ProverRequest::new(who, claim_address, self.asset.clone(), amount);
            let prover_message = BalanceProverMessageBuilder::default()
                .request(request)
                .sign_request(&self.pair())
                .build();

            Ok(prover_message)
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
