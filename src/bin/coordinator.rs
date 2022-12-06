use cerberus::{communication, parameters::GlobalParameters};
use futures::future;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{error::Error, fmt::Debug, thread, time};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // try to reach the other moderators
    let coordinator = Coordinator::new();

    // give the moderators a few seconds to spin up their servers
    // TODO query moderators until they respond
    println!("Waiting for moderators to spin up their servers...");
    thread::sleep(time::Duration::from_secs(2));

    let request = communication::healthcheck::Request {
        message: "Hello from the coordinator".into(),
    };
    let responses: Vec<communication::healthcheck::Response> = coordinator
        .query_moderators("healthcheck", &request)
        .await?;

    println!("{responses:#?}");

    Ok(())
}

pub struct Coordinator {
    params: GlobalParameters,
    client: reqwest::Client,
}

impl Coordinator {
    /// Creates a new
    fn new() -> Self {
        Coordinator {
            params: GlobalParameters::load()
                .expect("Failed to load environment variables."),
            client: reqwest::Client::new(),
        }
    }

    /// Sends a query to every moderator at the provided endpoint and with the provided body.
    ///
    /// Returns a vector of their responses or an error if something failed.
    async fn query_moderators<Req, Res>(
        &self,
        endpoint: &str,
        body: &Req,
    ) -> Result<Vec<Res>, Box<dyn Error>>
    where
        for<'a> Req: Serialize + Deserialize<'a> + Debug, // CHECK is this the correct way to do the lifetime param?
        Res: Serialize + DeserializeOwned + Debug,
    {
        future::try_join_all((1..=self.params.n).map(|i| async move {
            let url = format!("http://cerberus-moderator-{i}/{endpoint}");

            let response = self.client.get(&url).json(body).send().await?;

            // TODO check for non-2XX status

            let body: Res = response.json().await?;

            Ok(body)
        }))
        .await
    }
}
