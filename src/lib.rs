// #[warn(clippy::pedantic)]

use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};

mod communication;
mod elgamal;
mod roles;
mod token;

pub use parameters::{DECRYPTION_THRESHOLD, N_MODERATORS, SIGNING_THRESHOLD};
pub use roles::{coordinator::Coordinator, moderator::Moderator};

/// Protocol hyperparameters
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

    // Size of the token batches created during construction.
    // pub const BATCH_SIZE: usize =
    //     unwrap_ctx!(parse_usize(env!("CERBERUS_BATCH_SIZE")));
}

/// Wrapper type for an
#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct UserId([u8; 32]);

impl UserId {
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(rng.gen())
    }
}

// TODO
pub type UserPublicKey = [u8; 32];

/// Wrapper a single batch of something in the protocol, e.g.,
/// a batch of signature shares sent by a moderator to the coordinator.
type Batch<T> = Vec<T>;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
