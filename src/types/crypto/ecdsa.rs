use crate::types::{Error, Result};
use alloc::vec::Vec;
use k256::ecdsa::{SigningKey as SecretKey, VerifyingKey as PublicKey};
use pink_extension as pink;
use sp_core::Hasher;

use super::hasher::{ContractBlakeTwo256, ContractKeccak256};

/// The length of the secret seed
pub const SEED_LENGTH: usize = 32;

/// The length of the signature
pub const SIGNATURE_LENGTH: usize = 65;

/// The secret seed.
///
/// The raw secret seed, which can be used to create the `ContractKeyPair`.
type Seed = [u8; SEED_LENGTH];

/// The ECDSA signature
type Signature = [u8; SIGNATURE_LENGTH];

/// The ink storage to store the contract keyring material within the version.
#[derive(Debug)]
#[ink::storage_item]
pub struct ContractSeed {
    pub seed: Seed,
    pub version: u32,
}

/// The version of the contract `KeyPair`
pub struct KeyPairVersion(u32);

impl From<u32> for KeyPairVersion {
    fn from(value: u32) -> Self {
        KeyPairVersion(value)
    }
}

impl From<KeyPairVersion> for u32 {
    fn from(value: KeyPairVersion) -> Self {
        value.0
    }
}

impl KeyPairVersion {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn saturating_inc(&mut self) {
        if self.0 < u32::MAX {
            self.0 += 1;
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

/// The contract `KeyPair`
pub struct ContractKeyPair {
    public: PublicKey,
    secret: SecretKey,
    version: KeyPairVersion,
}

impl From<ContractKeyPair> for ContractSeed {
    fn from(value: ContractKeyPair) -> Self {
        ContractSeed {
            seed: value.seed(),
            version: value.version.into(),
        }
    }
}

impl ContractKeyPair {
    /// Get the contract `KeyPair` from a seed and its version
    pub fn from_versioned_seed(seed: &[u8], version: u32) -> Result<Self> {
        let secret = SecretKey::from_slice(&seed).map_err(|_| Error::InvalidSeedLength)?;

        Ok(ContractKeyPair {
            public: PublicKey::from(&secret),
            secret,
            version: version.into(),
        })
    }

    /// Generates a new contract `KeyPair`.
    ///
    /// Given a salt, it generates a `KeyPair` from a seed that is computed by first deriving a raw secret using the pink extension, that uses a contract inner secret, and then hashing the raw secret and key version number.
    pub fn generate(salt: &[u8]) -> Self {
        let secret = generate_secret_from_salt(salt);

        ContractKeyPair {
            public: PublicKey::from(&secret),
            secret,
            version: KeyPairVersion::new(),
        }
    }

    fn seed(&self) -> Seed {
        self.secret.to_bytes().into()
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// Derives a new version of the `KeyPair`
    pub fn derive_new_version(mut self) -> ContractKeyPair {
        let mut material = Vec::new();
        material.extend_from_slice(&self.seed());

        // Increment the version number
        self.version.saturating_inc();
        material.extend_from_slice(&self.version.to_vec());
        // salt = hash(old_seed + new_version)
        let salt = ContractBlakeTwo256::hash(&material);

        let secret = generate_secret_from_salt(salt.as_bytes());

        ContractKeyPair {
            public: PublicKey::from(&secret),
            secret,
            version: self.version,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let msg_hash = ContractKeccak256::hash(message);
        let recsig = self
            .secret
            .sign_prehash_recoverable(msg_hash.as_bytes())
            .expect("Signing can't fail when using 32 bytes message hash. qed.");

        let mut sig = [0u8; SIGNATURE_LENGTH];
        sig[..64].copy_from_slice(&recsig.0.to_bytes());
        sig[64] = recsig.1.to_byte();

        sig
    }
}

/// Generate a new secret from an input salt
fn generate_secret_from_salt(salt: &[u8]) -> SecretKey {
    let mut seed = [0u8; SEED_LENGTH];
    let raw_secret = pink::ext().derive_sr25519_key(salt.into());
    seed.copy_from_slice(&raw_secret);

    SecretKey::from_slice(&seed).expect("Seed is 32 bytes")
}
