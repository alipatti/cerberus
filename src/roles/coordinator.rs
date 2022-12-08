use crate::{
    communication as coms,
    parameters::{N_MODERATORS, SIGNING_THRESHOLD},
};

use frost_ristretto255 as frost;
use futures::future;
use rand::rngs::ThreadRng;
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::error::Error;

pub struct Coordinator {
    client: reqwest::Client,
    rng: ThreadRng,
}

// TODO make this private
pub enum OneOrMany<T> {
    One(T),
    Many([T; N_MODERATORS as usize]),
}

impl Coordinator {
    /// Creates a new coordinator object.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Coordinator {
            client: reqwest::Client::new(),
            rng: ThreadRng::default(),
        }
    }

    // TODO make this private
    /// Sends a query to every moderator at the provided endpoint and with the provided body.
    ///
    /// Returns an array of type [`Res`; [`N_MODERATORS`]]
    pub async fn query_moderators<Res: Serialize + DeserializeOwned>(
        &self,
        endpoint: &str,
        payload: &OneOrMany<impl Serialize + DeserializeOwned>,
    ) -> Result<[Res; N_MODERATORS], Box<dyn Error>> {
        // fetch all responses in parallel
        let responses: Vec<Res> =
            future::try_join_all((1..=N_MODERATORS).map(|i| async move {
                let url = format!("http://cerberus-moderator-{i}/{endpoint}");
                let body = match payload {
                    OneOrMany::One(body) => body,
                    OneOrMany::Many(bodies) => &bodies[i as usize],
                };

                let response = self.client.get(&url).json(body).send().await?;

                if response.status() != StatusCode::OK {
                    return Err(string_error::into_err(response.text().await?));
                }

                Ok(response.json().await?)
            }))
            .await?;

        Ok(responses.try_into().unwrap_or_else(|_| panic!()))
    }

    /// Distributes encryption and signing key shares to the moderators.
    ///
    /// In practice, this centralized share dealing can be replaced by a distributed key generation protocol such as [TODO fill this in].
    pub async fn setup(&mut self) -> Result<(), Box<dyn Error>> {
        // TODO implement DKG
        let (secret_shares, public_keys) = frost::keys::keygen_with_dealer(
            N_MODERATORS as u16,
            SIGNING_THRESHOLD as u16,
            &mut self.rng,
        )?;

        let request_bodies = secret_shares
            .into_iter()
            .map(|secret_share| coms::setup::Request { secret_share })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let responses: [coms::setup::Response; N_MODERATORS] = self
            .query_moderators("setup", &OneOrMany::Many(request_bodies))
            .await?;

        Ok(())
    }
}
