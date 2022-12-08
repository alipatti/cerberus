use frost::keys::SecretShare;
use frost_ristretto255 as frost;
use rand::thread_rng;
use std::error::Error;

// TODO move this to be a test in the FROST repo

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();
    let max_signers = 5;
    let min_signers = 3;

    let (shares, _) =
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng)?;
    let share = shares[0].to_owned();

    let bytes = bincode::serialize(&share)?;
    println!("{bytes:?}");

    let should_be_share: SecretShare = bincode::deserialize(&bytes)?;
    assert_eq!(should_be_share, share);

    Ok(())
}
