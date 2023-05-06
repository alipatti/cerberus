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

        /// The user ID to be encrypted.
        pub(crate) user_id: UserId,
    }
}

#[cfg(test)]
mod tests {

    use super::{
        setup,
        signing::{self, SigningRequest},
    };
    use crate::{
        elgamal::generate_private_key_shares, parameters::N_MODERATORS, Result,
        UserId,
    };
    use array_init::array_init;
    use curve25519_dalek::scalar::Scalar;
    use frost::{Identifier, SigningPackage};
    use frost_core::frost::keys::SigningShare;
    use frost_ristretto255 as frost;
    use rand::Rng;

    #[test]
    fn test_setup_serialization() -> Result<()> {
        let mut rng = rand::thread_rng();

        let frost_secret_share = {
            let (shares, _) = frost::keys::keygen_with_dealer(5, 3, &mut rng)?;

            shares[0].to_owned()
        };

        let elgamal_secret_share = {
            let (_, shares) = generate_private_key_shares(&mut rng);
            shares[0].to_owned()
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

    #[test]
    fn test_signing_serialization() -> Result<()> {
        // make dummy data
        let mut rng = rand::thread_rng();
        let signing_requests = array_init(|_i| {
            let signing_commitments = (0..N_MODERATORS)
                .map(|i| {
                    let participant_identifier =
                        Identifier::try_from((i + 1) as u16).unwrap();
                    let secret = SigningShare::from_bytes(
                        Scalar::random(&mut rng).to_bytes(),
                    )
                    .unwrap();
                    let (_nonces, commitment) = frost::round1::commit(
                        participant_identifier,
                        &secret,
                        &mut rng,
                    );
                    commitment
                })
                .collect();
            let message = (0..128).map(|_| 0).collect();
            SigningRequest {
                elgamal_randomness: Scalar::random(&mut rng),
                signing_package: SigningPackage::new(
                    signing_commitments,
                    message,
                ),
                user_id: UserId(rng.gen()),
            }
        });

        let request = signing::Request { signing_requests };

        let should_be_request: signing::Request = {
            let bytes = bincode::serialize(&request)?;
            bincode::deserialize(&bytes)?
        };

        assert_eq!(
            request.signing_requests[0].elgamal_randomness,
            should_be_request.signing_requests[0].elgamal_randomness
        );

        Ok(())
    }
}
