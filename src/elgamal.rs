use std::error::Error;

use crate::{
    parameters::{DECRYPTION_THRESHOLD, N_MODERATORS},
    Result, UserId,
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint,
    scalar::Scalar, traits::Identity,
};
use rand::rngs::ThreadRng;
use serde::{Deserialize, Serialize};
use vsss_rs::{curve25519::WrappedScalar, Shamir};

//  Map between Ristretto point and UserId
// -----------------------------------------

impl From<RistrettoPoint> for UserId {
    fn from(curve_point: RistrettoPoint) -> Self {
        // TODO implement https://eprint.iacr.org/2013/373.pdf
        unimplemented!()
    }
}

impl From<&UserId> for RistrettoPoint {
    fn from(val: &UserId) -> Self {
        // TODO implement https://eprint.iacr.org/2013/373.pdf
        let mut rng = ThreadRng::default();
        Self::random(&mut rng)
    }
}

//            Key implementations
// -----------------------------------------

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq)]
pub(crate) struct KeyShare {
    pub(crate) private: PrivateKey,
    pub(crate) public: PublicKey,
    pub(crate) group_public: PublicKey,
}

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq)]
pub(crate) struct PrivateKey(Scalar);

impl PrivateKey {
    pub(crate) fn public(&self) -> PublicKey {
        PublicKey(&self.0 * &RISTRETTO_BASEPOINT_TABLE)
    }

    /// Creates a group public elgamal key and an array of individual private keys.
    ///
    /// The decryption shares created by the private keys can be added
    /// (with appropriate Lagrange multipliers) to decrypt a message encoded with
    /// the group key.
    pub(crate) fn create_shares(&self) -> Result<[KeyShare; N_MODERATORS]> {
        let mut rng = ThreadRng::default();

        let shares_as_bytes = {
            // weird type conversion between different forks of the same curve25519 library
            let wrapped_scalar: WrappedScalar =
                curve25519_dalek_ml::scalar::Scalar::from_canonical_bytes(
                    self.0.to_bytes(),
                )
                .expect("Invalid scalar byte encoding")
                .into();

            Shamir {
                n: N_MODERATORS,
                t: DECRYPTION_THRESHOLD,
            }
            .split_secret(wrapped_scalar, &mut rng)
            .unwrap()
        };

        array_init::from_iter(
            shares_as_bytes
                .into_iter()
                .map(|share| -> Result<KeyShare> {
                    let bytes = share.value().try_into()?;
                    let scalar = Scalar::from_canonical_bytes(bytes).unwrap(); // TODO handle error
                    let private = PrivateKey(scalar);

                    Ok(KeyShare {
                        public: private.public(),
                        private,
                        group_public: self.public(),
                    })
                })
                .collect::<Result<Vec<KeyShare>>>()?,
        )
        .ok_or("Not enough shares".into())
    }

    pub(crate) fn random() -> Self {
        let mut rng = ThreadRng::default();
        Self(Scalar::random(&mut rng))
    }
}

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct PublicKey(RistrettoPoint);

impl PublicKey {
    pub(crate) fn encrypt(
        &self,
        user_id: &UserId,
        randomness: &Scalar,
    ) -> EncryptedUserId {
        let id_as_point: RistrettoPoint = user_id.into();

        EncryptedUserId {
            c_1: randomness * &RISTRETTO_BASEPOINT_TABLE,
            c_2: id_as_point + randomness * self.0,
        }
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(key: &PrivateKey) -> Self {
        Self(&key.0 * &RISTRETTO_BASEPOINT_TABLE)
    }
}

pub(crate) struct DecryptionShare {
    identifier: usize,
    share: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct EncryptedUserId {
    c_1: RistrettoPoint,
    c_2: RistrettoPoint,
}

impl EncryptedUserId {
    pub(crate) fn decrypt_with_shares(
        &self,
        shares: &[DecryptionShare; DECRYPTION_THRESHOLD],
    ) -> Result<UserId> {
        let mut sum = RistrettoPoint::identity();
        for share in shares {
            sum += share.share * lagrange_coefficient(share.identifier);
        }

        let user_as_point: RistrettoPoint = sum - self.c_2;

        Ok(user_as_point.into())
    }
}

fn lagrange_coefficient(identifier: usize) -> Scalar {
    todo!()
}

#[cfg(test)]
mod tests {

    #[test]
    fn test() {
        todo!()
    }
}
