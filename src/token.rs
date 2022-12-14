use crate::{
    elgamal::{self, EncryptedUserId},
    UserPublicKey,
};
use frost_ristretto255 as frost;
use serde::{Deserialize, Serialize};
use std::{error::Error, time::SystemTime};

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
    pub(crate) timestamp: SystemTime,
    pub(crate) encryption_of_id: EncryptedUserId,
    pub(crate) pk_e: UserPublicKey,
}
