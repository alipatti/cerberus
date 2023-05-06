// see: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing

use array_init::array_init;
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

use crate::parameters::{DECRYPTION_THRESHOLD, N_MODERATORS};

/// Represents a point `(x, f(x))` for an unknown polynomial `f`
/// of degree [DECRYPTION_THRESHOLD] - 1
pub(crate) struct SecretShare(Scalar, Scalar);

/// Returns an array of `SecretShares` that can be recombined using [`combine_shares`] to recover the original secret.
pub(crate) fn create_shares(secret: &Scalar) -> [SecretShare; N_MODERATORS] {
    let mut rng = thread_rng();

    // generate random polynomial coefficients
    let mut polynomial_coefficients = vec![secret.clone()];
    for _ in 1..DECRYPTION_THRESHOLD {
        polynomial_coefficients.push(Scalar::random(&mut rng))
    }

    // define polynomial that will be interpolated over:
    // x -> a_0 + a_1 x + a_2 x^2 + ... + a_{k-1} x^{k-1}
    let f = |x: u64| {
        polynomial_coefficients
            .iter()
            .zip(0..)
            .map(move |(a, k)| a * Scalar::from(x.pow(k)))
            .sum()
    };

    // generage shares `(x, f(x))` for `x = 1..N_MODERATORS`
    array_init(|i| SecretShare(Scalar::from(1 + i as u64), f(1 + i as u64)))
}

/// Calculate the lagrange coefficients for decryption shares.
fn lagrange_coefficient(
    share: &SecretShare,
    other_shares: &[SecretShare],
) -> Scalar {
    assert!(other_shares.len() == DECRYPTION_THRESHOLD);

    other_shares
        .iter()
        .filter(|other| other.0 != share.0) // take the product over all i != j
        .map(|other| other.0 * (other.0 - share.0).invert())
        .product()
}

pub(crate) fn combine_shares(shares: &[SecretShare]) -> Option<Scalar> {
    if shares.len() != DECRYPTION_THRESHOLD {
        return None; // wrong number of shares
    }

    Some(
        shares
            .iter()
            .map(|share| share.1 * lagrange_coefficient(share, shares))
            .sum(),
    )
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand::seq::SliceRandom;

    use crate::parameters::DECRYPTION_THRESHOLD;

    use super::{combine_shares, create_shares, lagrange_coefficient};

    #[test]
    fn test_share_creation() {
        let mut rng = rand::thread_rng();
        let shares = create_shares(&Scalar::random(&mut rng));

        // check that shares have correct indices
        assert!(shares
            .iter()
            .zip(1u32..)
            .all(|(share, i)| share.0 == Scalar::from(i)));
    }

    #[test]
    fn test_lagrange() {
        let mut rng = rand::thread_rng();
        let shares = create_shares(&Scalar::random(&mut rng));
        let coefficient =
            lagrange_coefficient(&shares[0], &shares[..DECRYPTION_THRESHOLD]);

        let share = &shares[0];
        let other_shares = &shares[1..DECRYPTION_THRESHOLD];
        assert_eq!(
            other_shares.len(),
            DECRYPTION_THRESHOLD - 1,
            "Incorrect number of shares."
        );

        let manual_coefficient = other_shares
            .iter()
            .map(|other| other.0 * (other.0 - share.0).invert())
            .product();

        assert_eq!(
            coefficient,
            manual_coefficient,
            "Manually calculated coefficient doesn't match coefficient calculated by function."
        );
    }

    #[test]
    fn test_secret_recovery() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);

        let mut shares = create_shares(&secret);

        // mix up the shares so we aren't just taking the first `k` every time
        shares.shuffle(&mut rng);

        // recombine k shares to get back the secret
        let recovered_secret = combine_shares(&shares[..DECRYPTION_THRESHOLD]);

        assert!(recovered_secret.is_some(), "Secret recovery failed");
        assert_eq!(
            secret,
            recovered_secret.unwrap(),
            "Recovered secret doesn't match original"
        );
    }
}
