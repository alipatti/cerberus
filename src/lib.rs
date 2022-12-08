// #[warn(clippy::pedantic)]

mod communication;
pub mod roles;

mod parameters {
    use konst::{primitive::parse_usize, unwrap_ctx};

    load_dotenv::load_dotenv!(); // load environment variables at compile time

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

struct UserId(u64);
type Batch<T> = [T; parameters::BATCH_SIZE];

mod token {
    use frost_ristretto255 as frost;
    use serde::{Deserialize, Serialize};
    use std::{error::Error, time::SystemTime};

    #[derive(Serialize, Deserialize)]
    pub struct SignedToken {
        pub signature: frost::Signature,
        // TODO fill in the rest
    }

    #[derive(Serialize, Deserialize)]
    pub(crate) struct UnsignedToken {
        // timestamp: SystemTime,
        id_encryption: u32, // TODO
        pk_e: u32,          // TODO
    }

    impl SignedToken {
        pub fn verify(&self) -> Result<(), Box<dyn Error>> {
            unimplemented!()
        }
    }
}
