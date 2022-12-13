// #[warn(clippy::pedantic)]

mod communication;
mod elgamal;
pub mod roles;
mod token;

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

pub struct UserId(u64);
pub type UserPublicKey = [u8; 32]; // TODO

type Batch<T> = [T; parameters::BATCH_SIZE];
