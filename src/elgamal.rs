use crate::{
    parameters::{DECRYPTION_THRESHOLD, N_MODERATORS},
    UserId,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint,
    scalar::Scalar, traits::Identity,
};
use rand::rngs::ThreadRng;
use std::error::Error;
use vsss_rs::{curve25519::WrappedScalar, Shamir};

//  Map between Ristretto point and UserId
// -----------------------------------------

impl From<RistrettoPoint> for UserId {
    fn from(curve_point: RistrettoPoint) -> Self {
        // https://eprint.iacr.org/2013/373.pdf
        unimplemented!()
    }
}

impl Into<RistrettoPoint> for &UserId {
    fn into(self) -> RistrettoPoint {
        // https://eprint.iacr.org/2013/373.pdf
        unimplemented!()
    }
}

//            Key implementations
// -----------------------------------------

struct PrivateKey(Scalar);

impl PrivateKey {
    // is this necessary?
    fn decrypt(&self, ciphertext: EncryptedUserId) -> UserId {
        unimplemented!()
    }

    fn decryption_share(&self, ciphertext: EncryptedUserId) -> DecryptionShare {
        unimplemented!()
    }

    /// Creates a group public elgamal key and an array of individual private keys.
    ///
    /// The decryption shares created by the private keys can be added
    /// (with appropriate Lagrange multipliers) to decrypt a message encoded with
    /// the group key.
    fn create_shares(
        &self,
    ) -> Result<[PrivateKey; N_MODERATORS], Box<dyn Error>> {
        let mut rng = ThreadRng::default();

        array_init::from_iter(
            Shamir {
                n: N_MODERATORS,
                t: DECRYPTION_THRESHOLD,
            }
            .split_secret::<WrappedScalar, ThreadRng>(self.0.into(), &mut rng)
            .unwrap()
            .into_iter()
            .map(|share| {
                // TODO handle errors
                let bytes = share.value().try_into().unwrap();
                let scalar = Scalar::from_canonical_bytes(bytes).unwrap();
                PrivateKey(scalar)
            }),
        )
        .ok_or_else(|| "Not enough shares".into())
    }
}

struct PublicKey(RistrettoPoint);

impl PublicKey {
    fn encrypt(
        &self,
        user_id: &UserId,
        randomness: Option<Scalar>,
    ) -> EncryptedUserId {
        let mut rng = ThreadRng::default();
        let randomness = randomness.unwrap_or_else(|| Scalar::random(&mut rng));
        let id_as_point: RistrettoPoint = user_id.into();

        EncryptedUserId {
            c_1: &randomness * &RISTRETTO_BASEPOINT_TABLE,
            c_2: id_as_point + randomness * self.0,
        }
    }
}

pub(crate) struct DecryptionShare {
    identifier: usize,
    share: RistrettoPoint,
}

pub(crate) struct EncryptedUserId {
    c_1: RistrettoPoint,
    c_2: RistrettoPoint,
}

impl EncryptedUserId {
    pub(crate) fn decrypt_with_shares(
        &self,
        shares: &[DecryptionShare; DECRYPTION_THRESHOLD],
    ) -> Result<UserId, Box<dyn Error>> {
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
