// #[warn(clippy::pedantic)]
#[macro_use]
extern crate dotenv_codegen;

pub mod communication;
pub mod roles;

pub mod parameters {
    use konst::{primitive::parse_u16, unwrap_ctx};

    // sorta hacky, but it works...

    pub const N_MODERATORS: u16 =
        unwrap_ctx!(parse_u16(dotenv!("CERBERUS_N_MODERATORS")));
    pub const SIGNING_THRESHOLD: u16 =
        unwrap_ctx!(parse_u16(dotenv!("CERBERUS_SIGNING_THRESHOLD")));
    pub const DECRYPTION_THRESHOLD: u16 =
        unwrap_ctx!(parse_u16(dotenv!("CERBERUS_ENCRYPTION_THRESHOLD")));
    pub const BATCH_SIZE: u16 =
        unwrap_ctx!(parse_u16(dotenv!("CERBERUS_BATCH_SIZE")));
}
