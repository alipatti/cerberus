use cerberus::roles::coordinator::Coordinator;
use std::{error::Error, thread, time};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // try to reach the other moderators

    println!("Waiting for moderators to spin up their servers...");
    // this could probably be more principled
    thread::sleep(time::Duration::from_secs(2));

    // start up coordinator
    // under the hood, this calls the
    let coordinator = Coordinator::init().await?;

    Ok(())
}
