use std::{env, error::Error};

/// Struct to hold public key material.
/// This is only for testing--in the real world, this would be replaced by a certificate authority.
pub struct PublicKeys {} // TODO

pub struct GlobalParameters {
    pub(crate) n: usize,
    pub(crate) t_enc: usize,
    pub(crate) t_sig: usize,
    pub(crate) keys: PublicKeys,
}

impl GlobalParameters {
    /// Load global parameters from environment variables or uses defaults if they are unset.
    pub fn load() -> Result<GlobalParameters, Box<dyn Error>> {
        Ok(GlobalParameters {
            n: env::var("HECATE_N").map_or(5, |var| var.parse().unwrap()),
            t_sig: env::var("HECATE_T_SIG").map_or(5, |var| var.parse().unwrap()),
            t_enc: env::var("HECATE_T_ENC").map_or(3, |var| var.parse().unwrap()),
            keys: PublicKeys {},
        })
    }
}
