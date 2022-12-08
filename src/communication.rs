/// Setup round of communication
pub mod ping {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub struct Request;

    #[derive(Deserialize, Serialize)]
    pub struct Response;
}

/// Setup round of communication
pub mod setup {

    use frost_ristretto255 as frost;
    use serde::{Deserialize, Serialize};

    use crate::Batch;

    #[derive(Deserialize, Debug, Serialize)]
    pub struct Request {
        pub secret_share: frost::keys::SecretShare,
    }

    #[derive(Deserialize, Serialize)]
    pub struct Response {
        // serde can't handle generic arrays by itself
        #[serde(with = "serde_arrays")]
        pub nonce_commitments: Batch<frost::round1::SigningCommitments>,
    }
}

// Signing round of communication
pub mod signing {
    use crate::Batch;
    use frost_ristretto255::{
        round1::SigningCommitments, round2::SignatureShare, SigningPackage,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub struct Request {
        #[serde(with = "serde_arrays")]
        pub signing_packages: Batch<SigningPackage>,
    }

    #[derive(Deserialize, Serialize)]
    pub(crate) struct Response {
        #[serde(with = "serde_arrays")]
        pub(crate) signature_shares: Batch<SignatureShare>,
        #[serde(with = "serde_arrays")]
        pub(crate) new_nonce_commitments: Batch<SigningCommitments>,
    }
}
