use crate::UserPublicKey;
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
    timestamp: SystemTime,
    encryption_of_id: cryptid::elgamal::Ciphertext,
    pk_e: UserPublicKey,
}

impl UnsignedToken {
    pub(crate) fn new(
        timestamp: SystemTime,
        encryption_of_id: cryptid::elgamal::Ciphertext,
        pk_e: UserPublicKey,
    ) -> Self {
        Self {
            timestamp,
            encryption_of_id,
            pk_e,
        }
    }

    pub(crate) fn sign() {
        unimplemented!()
    }
}

impl SignedToken {
    pub fn verify(&self) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}
