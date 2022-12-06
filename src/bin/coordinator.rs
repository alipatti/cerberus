use cerberus::coordinator::Coordinator;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello coordinator!");
    let coordinator = Coordinator::new();

    // ensure that all moderators are up and running

    coordinator.test().await;

    Ok(())
}
