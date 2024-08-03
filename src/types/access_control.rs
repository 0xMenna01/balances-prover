use super::{Error, Result};
use pink_extension::AccountId;

pub type SudoAccount = AccountId;

pub struct AccessControl {
    sudo: SudoAccount,
}

impl AccessControl {
    pub fn from_account(sudo: SudoAccount) -> Self {
        Self { sudo }
    }

    pub fn ensure_root(&self, who: AccountId) -> Result<()> {
        if self.sudo == who {
            return Ok(());
        }
        // `who` is not sudo
        Err(Error::BadOrigin)
    }
}
