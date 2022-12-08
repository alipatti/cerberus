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

    use crate::batches::CommitmentBatch;
    use frost_ristretto255 as frost;
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Debug, Serialize)]
    pub struct Request {
        pub secret_share: frost::keys::SecretShare,
    }

    #[derive(Deserialize, Serialize)]
    pub struct Response {
        // serde can't handle generic arrays by itself
        #[serde(with = "serde_arrays")]
        pub nonce_commitments: CommitmentBatch,
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
