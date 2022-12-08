// #[warn(clippy::pedantic)]

pub mod communication;
pub mod roles;

pub mod parameters {
    use konst::{primitive::parse_usize, unwrap_ctx};

    // load environment variables at compile time
    load_dotenv::load_dotenv!();

    /// The number of moderators
    pub const N_MODERATORS: usize =
        unwrap_ctx!(parse_usize(env!("CERBERUS_N_MODERATORS")));

    /// The maximum number of dishonest parties
    ///
    /// Must be smaller than [`N_MODERATORS`]
    pub const SIGNING_THRESHOLD: usize =
        unwrap_ctx!(parse_usize(env!("CERBERUS_SIGNING_THRESHOLD")));

    /// Must be smaller than [`N_MODERATORS`]
    pub const DECRYPTION_THRESHOLD: usize =
        unwrap_ctx!(parse_usize(env!("CERBERUS_ENCRYPTION_THRESHOLD")));

    /// Size of the token batches created during construction.
    pub const BATCH_SIZE: usize =
        unwrap_ctx!(parse_usize(env!("CERBERUS_BATCH_SIZE")));
}

mod batches {
    use crate::parameters::BATCH_SIZE;
    use crate::token::UnsignedToken;
    use frost_ristretto255 as frost;

    pub(crate) type NonceBatch = [frost::round1::SigningNonces; BATCH_SIZE];

    pub(crate) type CommitmentBatch =
        [frost::round1::SigningCommitments; BATCH_SIZE];

    pub(crate) type SignatureBatch =
        [frost::round2::SignatureShare; BATCH_SIZE];

    pub(crate) type UnsignedTokenBatch = [UnsignedToken; BATCH_SIZE];
}

mod token {
    use frost_ristretto255 as frost;
    use serde::{Deserialize, Serialize};
    use std::{error::Error, time::SystemTime};

    #[derive(Serialize, Deserialize)]
    pub struct SignedToken {
        signature: frost::Signature,
    }

    pub(crate) struct UnsignedToken {
        timestamp: SystemTime,
        id_encryption: u32, // TODO
        pk_e: u32,          // TODO
    }

    impl SignedToken {
        pub fn verify(&self) -> Result<(), Box<dyn Error>> {
            unimplemented!()
        }
    }

    impl UnsignedToken {
        pub(crate) fn sign_partial(
            frost_key_package: frost::keys::KeyPackage,
        ) -> frost::round2::SignatureShare {
            unimplemented!()
        }
    }
}
