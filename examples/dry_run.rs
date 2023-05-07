use cerberus::{Coordinator, UserId};
use std::{error::Error, thread, time};

/// This function does run through of all the main functionality of the protocol.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let batch_size = 100;
    let n_moderators = 5; // must be less than the number of moderator containers
    let decryption_threshold = 3;
    let signing_threshold = 3;

    println!("Waiting for moderators to spin up their servers...");
    thread::sleep(time::Duration::from_millis(1000));

    // setup moderators
    println!("Initializing moderators...");
    let mut coordinator = Coordinator::init(
        n_moderators,
        signing_threshold,
        decryption_threshold,
        batch_size,
    )
    .await?;

    let mut rng = rand::thread_rng();
    let user_ids = (0..batch_size).map(|_| UserId::random(&mut rng)).collect();

    println!("Creating token batch 1...");
    coordinator.create_tokens(&user_ids).await?;

    // sign another batch to make sure that nonces are being properly kept in sync
    println!("Creating token batch 2...");
    let tokens = coordinator.create_tokens(&user_ids).await?;

    // request decryption shares
    println!("Decrypting token...");
    let decrypted_user_id =
        coordinator.request_token_decryption(&tokens[0]).await?;

    assert_eq!(
        user_ids[0], decrypted_user_id,
        "Decrypted user ID is incorrect."
    );

    // shut down moderators
    println!("Shutting down moderators...");
    coordinator.shutdown_moderators().await?;

    // start them back up again to make sure it works
    println!("Restarting moderators...");
    Coordinator::init(
        n_moderators,
        signing_threshold,
        decryption_threshold,
        batch_size,
    )
    .await?;

    println!("All good! Shutting down...");

    Ok(())
}
