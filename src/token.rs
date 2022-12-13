use crate::{elgamal::EncryptedUserId, UserPublicKey};
use frost_ristretto255 as frost;
use serde::{Deserialize, Serialize};
use std::{error::Error, time::SystemTime};

#[derive(Serialize, Deserialize)]
pub struct SignedToken {
    pub signature: frost::Signature,
    pub token: UnsignedToken,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UnsignedToken {
    pub(crate) timestamp: SystemTime,
    pub(crate) encryption_of_id: EncryptedUserId,
    pub(crate) pk_e: UserPublicKey,
}

impl UnsignedToken {
    pub(crate) fn sign() {
        unimplemented!()
    }
}

impl SignedToken {
    pub fn verify(&self) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}
