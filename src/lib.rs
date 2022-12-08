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

    pub const BATCH_SIZE: usize =
        unwrap_ctx!(parse_usize(env!("CERBERUS_BATCH_SIZE")));
}
