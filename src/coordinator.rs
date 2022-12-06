use crate::parameters::GlobalParameters;
use futures::future;
use std::error::Error;

pub struct Coordinator {
    params: GlobalParameters,
    client: reqwest::Client,
}

impl Coordinator {
    /// Creates a new coordinator object and runs the key generation algorithm.
    pub fn new() -> Self {
        let coordinator = Self {
            params: GlobalParameters::load().expect(
                "Unable to load environment variables. Consult the README for information.",
            ),
            client: reqwest::Client::new(),
        };

        // TODO initiate key generation protocol

        coordinator
    }

    /// test function
    pub async fn test(&self) -> Result<(), Box<dyn Error>> {
        let body = http::Request {
            hello: "world".into(),
        };
        let responses = self.get_signature_shares(&body).await;

        println!("{responses:#?}");

        // TODO combine signatures shares

        Ok(())
    }

    /// Gets signatures shares from all the moderators
    async fn get_signature_shares(
        &self,
        body: &http::Request,
    ) -> Result<Vec<http::Response>, Box<dyn Error>> {
        let response_bodies = future::join_all((1..=self.params.n).map(|i| async move {
            let url = format!("https://cerberus-moderator-{i}");

            // TODO explicitly handle error cases
            let response = self.client.get(url).json(body).send().await.unwrap();
            let body: http::Response = response.json().await.unwrap();

            body
        }))
        .await;

        Ok(response_bodies)
    }

}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}

pub mod http {
    use serde::{Deserialize, Serialize};
    #[derive(Deserialize, Serialize, Debug)]
    pub struct Request {
        pub hello: String,
    }

    #[derive(Deserialize, Debug, Serialize)]
    pub struct Response {
        pub hello: String,
    }
}
