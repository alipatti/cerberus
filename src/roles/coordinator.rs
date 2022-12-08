use crate::{
    batches::CommitmentBatch,
    communication as coms,
    parameters::{N_MODERATORS, SIGNING_THRESHOLD},
};

use frost_ristretto255 as frost;
use futures::future;
use rand::rngs::ThreadRng;
use serde::{de::DeserializeOwned, Serialize};
use std::error::Error;

pub struct Coordinator {
    client: reqwest::Client,
    rng: ThreadRng,
    frost_public_key_package: frost::keys::PublicKeyPackage,

    /// Ordered like `nonce_commitments [moderator_index] [token_index]`
    nonce_commitments: [CommitmentBatch; N_MODERATORS],
}

enum OneOrMany<T> {
    One(T),
    Many([T; N_MODERATORS as usize]),
}

impl Coordinator {
    /// Sets up the coordinator and moderators
    ///
    /// Returns a new coordinator object if successful.
    pub async fn setup() -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        let mut rng = ThreadRng::default();

        // Ensure that all moderators are online and reachable.
        // TODO keep trying until it works
        Self::query_moderators::<coms::ping::Response>(
            &client,
            "ping",
            &OneOrMany::One(coms::ping::Request),
        )
        .await?;

        let (frost_public_key_package, nonce_commitments) = {
            let (secret_shares, public_keys) = frost::keys::keygen_with_dealer(
                N_MODERATORS as u16,
                SIGNING_THRESHOLD as u16,
                &mut rng,
            )?;

            let request_bodies = array_init::from_iter(secret_shares)
                .expect("Wrong number of secret_shares."); // this should never trigger

            let responses = Self::query_moderators::<coms::setup::Response>(
                &client,
                "setup",
                &OneOrMany::Many(request_bodies),
            )
            .await?;

            let nonce_commitments = array_init::from_iter(
                responses.iter().map(|response| response.nonce_commitments),
            )
            .expect("Not enough nonce commitments.");

            (public_keys, nonce_commitments)
        };

        Ok(Coordinator {
            client,
            rng,
            frost_public_key_package,
            nonce_commitments,
        })
    }

    /// Sends a query to every moderator at the provided endpoint and with the provided body.
    ///
    /// Returns an array of type [`Res`; [`N_MODERATORS`]]
    async fn query_moderators<Res: Serialize + DeserializeOwned>(
        client: &reqwest::Client,
        endpoint: &str,
        payload: &OneOrMany<impl Serialize + DeserializeOwned>,
    ) -> Result<[Res; N_MODERATORS], Box<dyn Error>> {
        array_init::from_iter(
            future::try_join_all((1..=N_MODERATORS).map(|i| async move {
                let url = format!("http://cerberus-moderator-{i}/{endpoint}");
                let body = match payload {
                    OneOrMany::One(body) => body,
                    OneOrMany::Many(bodies) => &bodies[i as usize],
                };

                let response = client.get(&url).json(body).send().await?;

                // error on non-200 responses
                if response.status() != reqwest::StatusCode::OK {
                    return Err(<Box<dyn Error>>::from(response.text().await?));
                }

                Ok(response.json().await?)
            }))
            .await?,
        )
        .ok_or_else(|| "Failed to convert response vector into array".into())
    }
}
