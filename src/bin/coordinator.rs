use cerberus::{communication::healthcheck, roles::coordinator::Coordinator};
use std::{error::Error, thread, time};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // try to reach the other moderators
    let coordinator = Coordinator::new();

    // TODO query moderators until they respond
    println!("Waiting for moderators to spin up their servers...");
    thread::sleep(time::Duration::from_secs(2));

    let request = healthcheck::Request {
        message: "Hello from the coordinator".into(),
    };
    let responses: Vec<healthcheck::Response> = coordinator
        .query_moderators("healthcheck", &request)
        .await?;

    println!("{responses:#?}");

    Ok(())
}
