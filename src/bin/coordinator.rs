use array_init::array_init;
use cerberus::{roles::coordinator::Coordinator, UserId};
use std::{error::Error, thread, time};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    // HACK this could probably be more principled
    println!("Waiting for moderators to spin up their servers...");
    thread::sleep(time::Duration::from_millis(500));

    // setup moderators
    println!("Initializing moderators...");
    let coordinator = Coordinator::init().await?;
    println!("Moderator setup successful.");

    // request tokens
    println!("Requesting a batch of tokens...");
    let user_ids = array_init(UserId);
    let _tokens = coordinator.create_tokens(&user_ids).await?;
    println!("Successfully signed tokens!");

    Ok(())
}
