/// Setup round of communication
pub mod setup {

    use frost_ristretto255 as frost;
    use serde::{Deserialize, Serialize};

    use crate::{elgamal, Batch};

    #[derive(Deserialize, Debug, Serialize)]
    pub(crate) struct Request {
        pub frost_secret_share: frost::keys::SecretShare,
        pub elgamal_secret_share: elgamal::KeyShare,
    }

    #[derive(Deserialize, Serialize)]
    pub(crate) struct Response {
        // serde can't handle generic arrays by itself
        #[serde(with = "serde_arrays")]
        pub nonce_commitments: Batch<frost::round1::SigningCommitments>,
    }
}

// Signing round of communication
pub mod signing {

    use crate::{Batch, UserId};
    use curve25519_dalek::scalar::Scalar;
    use frost_ristretto255::{
        round1::SigningCommitments, round2::SignatureShare, SigningPackage,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub(crate) struct Request {
        #[serde(with = "serde_arrays")]
        pub(crate) signing_requests: Batch<SigningRequest>,
    }

    #[derive(Deserialize, Serialize)]
    pub(crate) struct Response {
        #[serde(with = "serde_arrays")]
        pub(crate) signature_shares: Batch<SignatureShare>,
        #[serde(with = "serde_arrays")]
        pub(crate) new_nonce_commitments: Batch<SigningCommitments>,
    }

    #[derive(Deserialize, Serialize, Clone)]
    pub(crate) struct SigningRequest {
        pub(crate) signing_package: SigningPackage,
        /// Used to verify the well-formedness of the signing package.
        pub(crate) elgamal_randomness: Scalar,
        /// Used to verify the well-formedness of the signing package.
        pub(crate) user_id: UserId,
    }
}
