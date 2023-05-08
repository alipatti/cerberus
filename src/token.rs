use crate::{elgamal::EncryptedUserId, UserPublicKey};
use frost_ristretto255 as frost;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize, Deserialize, Clone)]
pub struct SignedToken {
    pub signature: frost::Signature,
    pub token: UnsignedToken,
}

impl SignedToken {
    pub fn verify(&self) -> Result<(), Box<dyn Error>> {
        // in practice, there would be more here

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UnsignedToken {
    pub(crate) timestamp: i64,
    pub(crate) x_1: EncryptedUserId,
    pub(crate) pk_e: UserPublicKey,
}

// (x1, t1, σ1,(pke, ske))
