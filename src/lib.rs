// #[warn(clippy::pedantic)]

use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};

mod communication;
mod elgamal;
mod roles;
mod token;

pub use roles::{coordinator::Coordinator, moderator::Moderator};

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
