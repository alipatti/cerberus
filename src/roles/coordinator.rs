use crate::{
    communication as coms,
    parameters::{N_MODERATORS, SIGNING_THRESHOLD},
};
use frost::keys::SecretShare;
use frost_ristretto255 as frost;
use futures::future;
use rand::rngs::ThreadRng;
use serde::{de::DeserializeOwned, Serialize};
use std::{error::Error, fmt::Debug};

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
    /// Returns a vector of their responses or an error if something failed.
    pub async fn query_moderators<Req, Res>(
        &self,
        endpoint: &str,
        payload: &OneOrMany<Req>,
    ) -> Result<Vec<Res>, Box<dyn Error>>
    where
        Req: Serialize + DeserializeOwned + Debug,
        Res: Serialize + DeserializeOwned + Debug,
    {
        // if a vector is passed, make sure that it's the right length
        if let OneOrMany::Many(vec) = payload {
            if vec.len() == N_MODERATORS as usize {
                return Err(string_error::into_err(format!(
                    "Incorrect number of request bodies. Expected: {}. Got: {}",
                    N_MODERATORS,
                    vec.len()
                )));
            }
        }

        // fetch all responses in parallel
        future::try_join_all((1..=N_MODERATORS).map(|i| async move {
            let url = format!("http://cerberus-moderator-{i}/{endpoint}");
            let body = match payload {
                OneOrMany::One(body) => body,
                OneOrMany::Many(bodies) => &bodies[i as usize],
            };

            let response = self.client.get(&url).json(body).send().await?;
            // TODO check for non-2XX status

            let body: Res = response.json().await?;

            Ok(body)
        }))
        .await
    }

    /// Distributes encryption and signing key shares to the moderators.
    ///
    /// In practice, this centralized share dealing can be replaced by a distributed key generation protocol such as [TODO fill this in].
    pub async fn setup(&mut self) -> Result<(), Box<dyn Error>> {
        // TODO implement DKG
        let (secret_shares, public_keys) = frost::keys::keygen_with_dealer(
            N_MODERATORS,
            SIGNING_THRESHOLD,
            &mut self.rng,
        )?;

        let request_bodies = secret_shares
            .into_iter()
            .map(|secret_share| coms::setup::Request { secret_share })
            .collect::<Vec<_>>()
            .try_into()
            .expect("Wrong number of secret shares");

        let responses: Vec<coms::setup::Response> = self
            .query_moderators("setup", &OneOrMany::Many(request_bodies))
            .await?;

        Ok(())
    }
}
