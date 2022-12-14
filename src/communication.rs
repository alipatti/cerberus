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
    use std::vec;

    use super::{
        setup,
        signing::{self, SigningRequest},
    };
    use crate::{elgamal, parameters::N_MODERATORS, Result, UserId};
    use array_init::array_init;
    use curve25519_dalek::scalar::Scalar;
    use frost::{round1::SigningCommitments, Identifier, SigningPackage};
    use frost_core::frost::keys::SigningShare;
    use frost_ristretto255 as frost;
    use rand::{thread_rng, Rng};

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

    #[test]
    fn test_signing_serde() -> Result<()> {
        // make dummy data
        let mut rng = thread_rng();
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

        Ok(())
    }

    #[test]
    fn test_signing_request_deserialization() -> Result<()> {
        let bytes: [u8; 840] = [
            2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 48, 229, 159, 94, 203, 222, 188, 138, 180, 13,
            98, 195, 167, 79, 62, 173, 17, 108, 167, 60, 53, 143, 81, 77, 208,
            49, 34, 9, 39, 113, 75, 50, 134, 166, 195, 109, 190, 34, 136, 229,
            50, 104, 194, 72, 175, 176, 121, 47, 132, 134, 151, 63, 107, 178,
            34, 84, 110, 208, 51, 234, 180, 35, 28, 94, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 110, 173, 103, 231, 182, 0, 69,
            105, 83, 93, 45, 117, 108, 235, 33, 74, 151, 156, 65, 38, 181, 56,
            72, 23, 29, 201, 43, 151, 182, 35, 154, 40, 142, 207, 140, 13, 220,
            67, 173, 29, 214, 38, 4, 94, 160, 40, 184, 111, 145, 112, 122, 177,
            15, 73, 127, 248, 141, 174, 33, 167, 1, 215, 113, 27, 108, 0, 0, 0,
            0, 0, 0, 0, 53, 70, 154, 99, 0, 0, 0, 0, 222, 228, 84, 54, 228, 63,
            34, 85, 83, 1, 19, 247, 202, 251, 24, 195, 158, 47, 95, 225, 245,
            242, 139, 78, 129, 28, 32, 47, 255, 120, 46, 113, 154, 236, 121,
            14, 230, 169, 76, 9, 150, 162, 94, 48, 116, 80, 83, 120, 128, 33,
            131, 99, 14, 168, 213, 123, 87, 166, 59, 177, 112, 67, 40, 121,
            191, 229, 254, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 74, 223, 136, 154,
            81, 151, 44, 161, 203, 144, 18, 96, 233, 235, 60, 175, 255, 95, 93,
            156, 63, 155, 173, 40, 33, 6, 47, 205, 3, 169, 218, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 152, 186, 10, 29, 241, 16, 83, 68,
            248, 227, 56, 10, 42, 70, 96, 38, 145, 253, 121, 213, 14, 76, 44,
            173, 23, 71, 171, 166, 150, 172, 13, 27, 76, 110, 149, 94, 20, 174,
            21, 210, 222, 184, 235, 129, 198, 88, 197, 198, 113, 8, 250, 192,
            120, 97, 252, 136, 242, 84, 178, 96, 14, 232, 95, 61, 2, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 231, 71, 32,
            234, 97, 222, 19, 229, 220, 66, 221, 82, 49, 26, 65, 155, 176, 159,
            136, 15, 223, 181, 37, 76, 176, 67, 222, 15, 98, 225, 55, 236, 156,
            251, 33, 212, 250, 97, 23, 81, 149, 195, 60, 153, 247, 34, 183,
            108, 251, 115, 122, 171, 238, 188, 252, 181, 79, 144, 78, 243, 23,
            33, 26, 108, 0, 0, 0, 0, 0, 0, 0, 53, 70, 154, 99, 0, 0, 0, 0, 151,
            179, 104, 54, 166, 160, 52, 44, 43, 73, 162, 10, 217, 149, 34, 202,
            156, 52, 233, 158, 121, 243, 47, 79, 252, 91, 57, 52, 253, 94, 141,
            249, 194, 47, 194, 37, 162, 157, 85, 176, 222, 238, 175, 228, 245,
            107, 160, 188, 253, 154, 163, 37, 120, 125, 50, 63, 123, 182, 244,
            143, 116, 243, 8, 17, 51, 71, 13, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            7, 101, 179, 67, 144, 91, 200, 211, 166, 101, 118, 47, 17, 241,
            187, 128, 57, 93, 230, 218, 28, 19, 227, 147, 9, 10, 125, 187, 26,
            87, 7, 8, 1, 0, 0, 0, 0, 0, 0, 0,
        ];

        let signing_request: signing::Request = bincode::deserialize(&bytes)?;

        Ok(())
    }
}
