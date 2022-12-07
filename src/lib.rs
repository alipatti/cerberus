// #[warn(clippy::pedantic)]
pub mod roles;

pub mod communication {
    /// Setup round of communication
    pub mod healthcheck {
        use serde::{Deserialize, Serialize};

        #[derive(Deserialize, Serialize, Debug)]
        pub struct Request {
            pub message: String,
        }

        #[derive(Deserialize, Debug, Serialize)]
        pub struct Response {
            pub message: String,
        }
    }

    /// Setup round of communication
    pub mod setup {
        use frost_ristretto255 as frost;
        use serde::{Deserialize, Serialize};

        pub struct Request {
            pub signing_share: frost::keys::SecretShare,
        }

        #[derive(Deserialize, Debug, Serialize)]
        pub struct Response {
            pub hello: String,
        }
    }

    // Signing round of communication
    pub mod signing {
        use serde::{Deserialize, Serialize};

        #[derive(Deserialize, Serialize, Debug)]
        pub struct Request {
            pub hello: String,
        }

        #[derive(Deserialize, Debug, Serialize)]
        pub struct Response {
            pub hello: String,
        }
    }
}

pub mod parameters {
    use std::{env, error::Error};

    /// Struct to hold public key material.
    /// This is only for testing--in the real world, this would be replaced by a certificate authority.
    #[derive(Debug)]
    pub struct PublicKeys {} // TODO

    #[derive(Debug)]
    pub struct GlobalParameters {
        pub n_moderators: u16,
        pub decryption_threshold: u16,
        pub signature_threshold: u16,
        pub keys: PublicKeys,
    }

    impl GlobalParameters {
        /// Load global parameters from environment variables or uses defaults if they are unset.
        pub fn load() -> Result<GlobalParameters, Box<dyn Error>> {
            Ok(GlobalParameters {
                n_moderators: env::var("CERBERUS_N")
                    .map_or(5, |var| var.parse().unwrap()),
                signature_threshold: env::var("CERBERUS_T_SIG")
                    .map_or(5, |var| var.parse().unwrap()),
                decryption_threshold: env::var("CERBERUS_T_ENC")
                    .map_or(3, |var| var.parse().unwrap()),
                keys: PublicKeys {},
            })
        }
    }
}
