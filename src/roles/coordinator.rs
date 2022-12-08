use crate::{
    communication as coms,
    parameters::{N_MODERATORS, SIGNING_THRESHOLD},
    token::{self, SignedToken, UnsignedToken},
    Batch,
};

use frost::{round1::SigningCommitments, SigningPackage};
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
    nonce_commitments: [Batch<frost::round1::SigningCommitments>; N_MODERATORS],
}

enum ModeratorRequest<'a, T> {
    One(&'a T),
    Many(&'a [T; N_MODERATORS]),
}

type ModeratorResponses<Res> = [Res; N_MODERATORS];

impl Coordinator {
    /// Sets up the coordinator and moderators
    ///
    /// Returns a new coordinator object if successful.
    pub async fn setup() -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        let mut rng = ThreadRng::default();

        // Ensure that all moderators are online and reachable.
        // TODO keep trying until it works
        Self::query_moderators::<_, coms::ping::Response>(
            &client,
            "ping",
            ModeratorRequest::One(&coms::ping::Request),
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

            let responses = Self::query_moderators::<_, coms::setup::Response>(
                &client,
                "setup",
                ModeratorRequest::Many(&request_bodies),
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

    async fn sign_token_batch(
        &self,
        unsigned_tokens: Batch<UnsignedToken>,
    ) -> Result<Batch<SignedToken>, Box<dyn Error>> {
        let signing_packages = array_init::try_array_init(
            |token_index| -> Result<SigningPackage, Box<dyn Error>> {
                // serialize the token so it can be passed to frost::sign()
                let serialized_token: Vec<u8> =
                    bincode::serialize(&unsigned_tokens[token_index])?;

                // collect the signing_commitments for this specific token
                let signing_commitments: Vec<SigningCommitments> = (0
                    ..N_MODERATORS)
                    .map(|moderator_index| {
                        self.nonce_commitments[moderator_index][token_index]
                    })
                    .collect();

                // create the signing package
                Ok(frost::round2::SigningPackage::new(
                    signing_commitments,
                    serialized_token,
                ))
            },
        )?;

        // FIX sorta hacky
        // maybe make the query_moderators function take references to the data itself instead of wrapping it in a request struct
        let request = coms::signing::Request {
            signing_packages: signing_packages.clone(),
        };

        // get signature shares from each moderator for all tokens in the batch
        let moderator_responses =
            Self::query_moderators::<_, coms::signing::Response>(
                &self.client,
                "sign",
                ModeratorRequest::One(&request),
            )
            .await?;

        // package the results as a SignedTokenBatch batch
        let signed_tokens: Batch<SignedToken> = array_init::try_array_init(
            |token_index| -> Result<SignedToken, Box<dyn Error>> {
                let signature_shares: Vec<_> = moderator_responses
                    .iter()
                    .map(|response| response.signature_shares[token_index])
                    .collect();

                let signature = frost::aggregate(
                    &signing_packages[token_index],
                    &signature_shares,
                    &self.frost_public_key_package,
                )?;

                Ok(SignedToken { signature })
            },
        )?;

        Ok(signed_tokens)
    }

    /// Sends a query to every moderator at the provided endpoint and with the provided body.
    ///
    /// Returns an array of type [`Res`; [`N_MODERATORS`]]
    /// TODO add description for [`OneOrMany`]
    async fn query_moderators<Req, Res>(
        client: &reqwest::Client,
        endpoint: &str,
        payload: ModeratorRequest<'_, Req>,
    ) -> Result<ModeratorResponses<Res>, Box<dyn Error>>
    where
        Req: Serialize + DeserializeOwned,
        Res: Serialize + DeserializeOwned,
    {
        let payload = &payload;
        array_init::from_iter(
            future::try_join_all((1..=N_MODERATORS).map(|i| async move {
                let url = format!("http://cerberus-moderator-{i}/{endpoint}");
                let body = match payload {
                    ModeratorRequest::One(body) => body,
                    ModeratorRequest::Many(bodies) => &bodies[i],
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
