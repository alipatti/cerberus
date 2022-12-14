use cerberus::roles::coordinator::Coordinator;
use std::{error::Error, thread, time};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // this could probably be more principled
    println!("Waiting for moderators to spin up their servers...");
    thread::sleep(time::Duration::from_secs(2));

    let _coordinator = Coordinator::init().await?;

    Ok(())
}
