use crate::{
    parameters::{DECRYPTION_THRESHOLD, N_MODERATORS},
    UserId,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint,
    scalar::Scalar, traits::Identity,
};
use rand::rngs::ThreadRng;
use sha2::Sha512;
use std::error::Error;
use vsss_rs::{curve25519::WrappedScalar, Shamir};

impl From<RistrettoPoint> for UserId {
    fn from(curve_point: RistrettoPoint) -> Self {
        unimplemented!()
    }
}

impl Into<RistrettoPoint> for UserId {
    fn into(self) -> RistrettoPoint {
        unimplemented!()
    }
}

struct EncryptedUserId(RistrettoPoint);

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
    fn create_shares(&self) -> Result<[Scalar; N_MODERATORS], Box<dyn Error>> {
        let mut rng = ThreadRng::default();

        let private_key_shares: [Scalar; N_MODERATORS] = array_init::from_iter(
            Shamir {
                n: N_MODERATORS,
                t: DECRYPTION_THRESHOLD,
            }
            .split_secret::<WrappedScalar, ThreadRng>(self.0.into(), &mut rng)
            .unwrap()
            .into_iter()
            .map(|share| {
                // TODO handle errors
                let bytes: [u8; 32] = share.value().try_into().unwrap();
                let scalar = Scalar::from_canonical_bytes(bytes).unwrap();

                scalar
            }),
        )
        .unwrap(); // TODO handle error

        Ok(private_key_shares)
    }
}

struct PublicKey(RistrettoPoint);

impl PublicKey {
    fn encrypt(
        &self,
        user_id: &UserId,
        randomness: Option<Scalar>,
    ) -> Ciphertext {
        let mut rng = ThreadRng::default();
        let randomness = randomness.unwrap_or_else(|| Scalar::random(&mut rng));
        let message =
            RistrettoPoint::hash_from_bytes::<Sha512>(&user_id.0.to_be_bytes());

        Ciphertext {
            c_1: &randomness * &RISTRETTO_BASEPOINT_TABLE,
            c_2: message + randomness * self.0,
        }
    }
}

struct DecryptionShare(RistrettoPoint);

struct Ciphertext {
    c_1: RistrettoPoint,
    c_2: RistrettoPoint,
}

impl Ciphertext {
    fn decrypt_with_shares(
        shares: &[DecryptionShare; DECRYPTION_THRESHOLD],
    ) -> Result<UserId, Box<dyn Error>> {
        let mut product = RistrettoPoint::id();
    }
}

// impl DecryptionShare {
//     fn create(c: Ciphertext, key: RistrettoPoint)
// }
