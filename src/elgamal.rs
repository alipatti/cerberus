use crate::{
    // parameters::{DECRYPTION_THRESHOLD, N_MODERATORS},
    Result,
    UserId,
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint,
    scalar::Scalar,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq)]
pub(crate) struct KeyShare {
    identifier: Scalar, // x
    sk: Scalar,         // f(x)
    pk: PublicKey,
}

/// Wrapper around a single Ristretto point.
/// Equivalent to `x * G` where `y` is the private key and `G`
/// is the Ristretto base point.
#[derive(Serialize, Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(RistrettoPoint);

/// An ElGamal encryption of a
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EncryptedUserId {
    c_1: RistrettoPoint,
    c_2: [u8; 32],
}

/// Wrapper for a decryption shares `(x, d)` where `d = f(x) * c_1` is
/// the product of the Shamir secret share and the the first entry
/// of the ElGamal ciphertext tuple, `c_1`.
#[derive(Deserialize, Serialize)]
pub struct DecryptionShare(Scalar, RistrettoPoint);

impl PublicKey {
    pub(crate) fn encrypt(
        &self,
        user_id: &UserId,
        randomness: &Scalar,
    ) -> EncryptedUserId {
        // compute c_1 = r * G
        let c_1 = randomness * &RISTRETTO_BASEPOINT_TABLE;

        // compute c_2 = ID + H(r * PK)
        let mut hasher = Sha256::new();
        hasher.update((randomness * self.0).compress().as_bytes());
        let hashed_point = hasher.finalize()[..]
            .try_into()
            .expect("Unable to hash Ristretto point during ID encryption.");

        let c_2 = xor_bytes(hashed_point, &user_id.0);

        EncryptedUserId { c_1, c_2 }
    }
}

impl KeyShare {
    pub(crate) fn decryption_share(
        &self,
        x_1: &EncryptedUserId,
    ) -> DecryptionShare {
        DecryptionShare(self.identifier, self.sk * x_1.c_1)
    }

    pub(crate) fn encrypt(
        &self,
        user_id: &UserId,
        randomness: &Scalar,
    ) -> EncryptedUserId {
        self.pk.encrypt(user_id, randomness)
    }
}

impl EncryptedUserId {
    /// The length of `shares` MUST be exactly the decryption threshold and every share MUST be unique.
    pub fn decrypt_with_shares(
        &self,
        shares: &[DecryptionShare],
    ) -> Result<UserId> {
        // TODO: extract this into a separate function
        let identifiers: Vec<_> = shares.iter().map(|share| share.0).collect();

        let sum_of_decryption_shares: RistrettoPoint = shares
            .iter()
            .map(|share| lagrange_coefficient(&share.0, &identifiers) * share.1)
            .sum();

        let mut hasher = Sha256::new();
        hasher.update(sum_of_decryption_shares.compress().as_bytes());
        let decryption_share_bytes = hasher.finalize()[..]
            .try_into()
            .expect("Failed to compute hash during ID decryption");

        let decrypted_id = UserId(xor_bytes(decryption_share_bytes, &self.c_2));

        Ok(decrypted_id)
    }
}

/// In practice, this would be done in a distributed fashion without a
/// trusted central party.
pub(crate) fn generate_private_key_shares<R: RngCore + CryptoRng>(
    rng: &mut R,
    n_shares: usize,
    decryption_threshold: usize,
) -> (PublicKey, Vec<KeyShare>) {
    // secret to be split up
    let sk = Scalar::random(rng);

    // generate random polynomial coefficients
    // to be used in Shamir secret sharing
    let mut polynomial_coefficients = vec![sk];
    for _ in 1..decryption_threshold {
        polynomial_coefficients.push(Scalar::random(rng))
    }

    // define the polynomial that will be interpolated
    // to recover the secret
    // f(x) = a_0 + a_1 x + a_2 x^2 + ... + a_{k-1} x^{k-1}
    let f = |x: u64| {
        polynomial_coefficients
            .iter()
            .zip(0..)
            .map(move |(a, k)|             a * Scalar::from(
                x.checked_pow(k)
                .expect("Exponentiation overflow during computation of Shamir polynomial."))
            )
            .sum()
    };

    let pk = PublicKey(&sk * &RISTRETTO_BASEPOINT_TABLE);

    // generate shares `(x, f(x))` for `x = 1..N_MODERATORS`
    let sk_shares = (1..=n_shares)
        .map(|i| KeyShare {
            identifier: Scalar::from(i as u64),
            sk: f(i as u64),
            pk,
        })
        .collect();

    (pk, sk_shares)
}

fn xor_bytes(mut a: [u8; 32], b: &[u8; 32]) -> [u8; 32] {
    for i in 0..32 {
        a[i] ^= b[i]
    }

    a
}

/// Calculate the lagrange coefficients for decryption shares.
/// The length of `other_identifiers` MUST be equal to the decryption threshold.
pub(crate) fn lagrange_coefficient(
    identifier: &Scalar,
    other_identifiers: &[Scalar],
) -> Scalar {
    other_identifiers
        .iter()
        .filter(|other| *other != identifier) // take the product over all i != j
        .map(|other| other * (other - identifier).invert())
        .product()
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand::Rng;

    use crate::UserId;

    use super::generate_private_key_shares;

    #[test]
    fn test_decryption() {
        let n_shares = 7;
        let decryption_threshold = 4;

        let mut rng = rand::thread_rng();

        let (pk, shares) = generate_private_key_shares(
            &mut rng,
            n_shares,
            decryption_threshold,
        );

        let id = UserId(rng.gen());

        let x_1 = pk.encrypt(&id, &Scalar::random(&mut rng));

        let decryption_shares: Vec<_> = shares[..decryption_threshold]
            .iter()
            .map(|share| share.decryption_share(&x_1))
            .collect();

        let id_decrypted = x_1.decrypt_with_shares(&decryption_shares);

        assert!(id_decrypted.is_ok(), "Unable to decrypt id");

        assert_eq!(id, id_decrypted.unwrap(), "Decrypted id is incorrect");
    }
}
