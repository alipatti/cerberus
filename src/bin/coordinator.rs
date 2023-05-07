use cerberus::{Coordinator, UserId};
use std::{error::Error, thread, time};

/// This function just does a quick call of each of the
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    // HACK this could probably be more principled
    let batch_size = 100;

    println!("Waiting for moderators to spin up their servers...");
    thread::sleep(time::Duration::from_millis(1000));

    // setup moderators
    println!("Initializing moderators...");
    let mut coordinator = Coordinator::init(batch_size).await?; // needs to be mutable to update nonce commitments
    println!("Successfully setup moderators!.");

    // request tokens
    println!("Requesting a batch of tokens...");
    let mut rng = rand::thread_rng();
    let user_ids = (0..batch_size).map(|_| UserId::random(&mut rng)).collect();

    coordinator.create_tokens(&user_ids).await?;
    println!("Successfully signed token batch 1!");

    // sign another batch to make sure that nonces are being properly kept in sync
    let tokens = coordinator.create_tokens(&user_ids).await?;
    println!("Successfully signed token batch 2!");

    // request decryption shares
    println!("Requesting decryption shares...");
    let decrypted_user_id =
        coordinator.request_token_decryption(&tokens[0]).await?;

    assert_eq!(
        user_ids[0], decrypted_user_id,
        "Decrypted user ID is incorrect."
    );
    println!("Successfully decrypted token!");

    // shut down moderators
    println!("Shutting down moderators...");
    coordinator.shutdown_moderators().await?;

    // start them back up again to make sure it works
    println!("Initializing moderators for the second time...");
    Coordinator::init(batch_size).await?;
    println!("Successfully setup moderators for the second time!");

    Ok(())
}
