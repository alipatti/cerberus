use cerberus::{Coordinator, UserId};
use std::{error::Error, thread, time};

/// This function just does a quick call of each of the
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    // HACK this could probably be more principled
    let BATCH_SIZE = 100;

    println!("Waiting for moderators to spin up their servers...");
    thread::sleep(time::Duration::from_millis(500));

    // setup moderators
    println!("Initializing moderators...");
    let coordinator = Coordinator::init(BATCH_SIZE).await?;
    println!("Successfully setup moderators!.");

    // request tokens
    println!("Requesting a batch of tokens...");
    let mut rng = rand::thread_rng();
    let user_ids = (0..BATCH_SIZE)
        .map(|_| UserId::random(&mut rng))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let tokens = coordinator.create_tokens(&user_ids).await?;
    println!("Successfully signed tokens!");

    // request decryption shares
    println!("Requesting decryption shares...");
    let decrypted_user_id =
        coordinator.request_token_decryption(&tokens[0]).await?;
    assert_eq!(
        user_ids[0], decrypted_user_id,
        "Decrypted user ID is incorrect."
    );
    println!("Successfully decrypted token!");

    Ok(())
}
