use crate::{
    elgamal::{self, EncryptedUserId},
    UserPublicKey,
};
use frost_ristretto255 as frost;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize, Deserialize)]
pub struct SignedToken {
    pub signature: frost::Signature,
    pub token: UnsignedToken,
}

impl SignedToken {
    pub fn verify(
        &self,
        public_key: elgamal::PublicKey,
    ) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UnsignedToken {
    pub(crate) timestamp: i64,
    pub(crate) x_1: EncryptedUserId,
    pub(crate) pk_e: UserPublicKey,
}
