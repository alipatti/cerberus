/// Setup round of communication
pub mod setup {

    use crate::{elgamal, Batch};
    use frost_ristretto255 as frost;
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub(crate) struct Request {
        pub frost_secret_share: frost::keys::SecretShare,
        pub elgamal_secret_share: elgamal::KeyShare,
    }

    #[derive(Deserialize, Serialize)]
    pub(crate) struct Response {
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

#[cfg(test)]
mod tests {
    use super::setup;
    use crate::{elgamal, Result};
    use frost_ristretto255 as frost;
    use rand::thread_rng;

    #[test]
    fn test_setup_serde() -> Result<()> {
        let frost_secret_share = {
            let (shares, _) =
                frost::keys::keygen_with_dealer(5, 3, &mut thread_rng())?;

            shares[0].to_owned()
        };

        let elgamal_secret_share = {
            let private = elgamal::PrivateKey::random();
            let public = private.public();
            elgamal::KeyShare {
                group_public: public.clone(),
                public,
                private,
            }
        };

        let request = setup::Request {
            frost_secret_share,
            elgamal_secret_share,
        };

        let bytes = bincode::serialize(&request)?;

        let should_be_request: setup::Request = bincode::deserialize(&bytes)?;

        assert_eq!(
            request.elgamal_secret_share,
            should_be_request.elgamal_secret_share,
            "Elgamal secret is not equal to the original."
        );

        assert_eq!(
            request.frost_secret_share.value,
            should_be_request.frost_secret_share.value,
            "Frost secret is not equal to the original."
        );

        Ok(())
    }

    fn test_signing_serde() -> Result<()> {
        unimplemented!()
    }
}
