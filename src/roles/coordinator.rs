use crate::{
    communication as coms,
    parameters::{N_MODERATORS, SIGNING_THRESHOLD},
    token::{SignedToken, UnsignedToken},
    Batch, UserId,
};
use frost::{keys::PublicKeyPackage, SigningPackage};
use frost_ristretto255 as frost;
use futures::future;
use rand::{rngs::ThreadRng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use std::{error::Error, time::SystemTime};

/// Nonce commitments from from all the moderators. Good for ONE batch of token-signing.
/// Ordered like `nonce_commitments [moderator_index] [batch_index]`
type CommitmentBatch = [Batch<frost::round1::SigningCommitments>; N_MODERATORS];

pub struct Coordinator {
    pub frost_public_key_package: frost::keys::PublicKeyPackage,
    client: reqwest::Client,

    nonce_commitments: CommitmentBatch,
}

enum ModeratorRequest<'a, T> {
    One(&'a T),
    Many(&'a [T; N_MODERATORS]),
}

type ModeratorResponses<Res> = [Res; N_MODERATORS];

impl Coordinator {
    pub async fn create_tokens(
        &self,
        user_ids: Batch<UserId>,
    ) -> Result<Batch<SignedToken>, Box<dyn Error>> {
        // TODO
        let mut rng = ThreadRng::default();
        let unsigned_tokens = array_init::map_array_init(&user_ids, |id| {
            let mut pk_e = [0u8; 32];
            rng.fill(&mut pk_e);

            let timestamp = SystemTime::now();
            let mut elgamal_randomness = [0u8; 32];
            rng.fill(&mut elgamal_randomness);

            UnsignedToken::new(timestamp, todo!(), pk_e);
        });
        self.sign_token_batch(unsigned_tokens).await
    }

    /// Sets up the coordinator and moderators
    ///
    /// Returns a new coordinator object if successful.
    pub async fn init() -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();

        let (frost_public_key_package, nonce_commitments) =
            Self::setup_moderators(&client).await?;

        Ok(Coordinator {
            client,
            frost_public_key_package,
            nonce_commitments,
        })
    }

    /// Sends a query to every moderator at the provided endpoint and with the provided body.
    ///
    /// Returns an array of type [`Res`; [`N_MODERATORS`]]
    async fn query_moderators<Req, Res>(
        client: &reqwest::Client,
        payload: ModeratorRequest<'_, Req>,
    ) -> Result<ModeratorResponses<Res>, Box<dyn Error>>
    where
        Req: Serialize + DeserializeOwned,
        Res: Serialize + DeserializeOwned,
    {
        let payload = &payload;
        array_init::from_iter(
            future::try_join_all((1..=N_MODERATORS).map(|i| async move {
                let url = format!("http://cerberus-moderator-{i}/");
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

    async fn setup_moderators(
        client: &reqwest::Client,
    ) -> Result<(PublicKeyPackage, CommitmentBatch), Box<dyn Error>> {
        let mut rng = ThreadRng::default();

        let (secret_shares, public_keys) = frost::keys::keygen_with_dealer(
            N_MODERATORS as u16,
            SIGNING_THRESHOLD as u16,
            &mut rng,
        )?;

        let request_bodies = array_init::from_iter(secret_shares)
            .expect("Wrong number of secret_shares."); // this should never trigger

        let responses = Self::query_moderators::<_, coms::setup::Response>(
            client,
            ModeratorRequest::Many(&request_bodies),
        )
        .await?;

        let nonce_commitments = array_init::from_iter(
            responses.iter().map(|response| response.nonce_commitments),
        )
        .expect("Not enough nonce commitments.");

        Ok((public_keys, nonce_commitments))
    }

    async fn sign_token_batch(
        &self,
        unsigned_tokens: Batch<UnsignedToken>,
    ) -> Result<Batch<SignedToken>, Box<dyn Error>> {
        let signing_packages = array_init::try_array_init(
            |token_index| -> Result<SigningPackage, Box<dyn Error>> {
                // serialize the token so it can be passed to frost::sign()
                let token_bytes =
                    bincode::serialize(&unsigned_tokens[token_index])?;

                // collect the signing_commitments for this specific token
                // (use a vector because that's what FROST accepts)
                let signing_commitments = (0..N_MODERATORS)
                    .map(|moderator_index| {
                        self.nonce_commitments[moderator_index][token_index]
                    })
                    .collect();

                // create the signing package
                Ok(frost::round2::SigningPackage::new(
                    signing_commitments,
                    token_bytes,
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
                ModeratorRequest::One(&request),
            )
            .await?;

        // package the results as a SignedToken batch
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

                Ok(SignedToken {
                    signature,
                    token: todo!(),
                })
            },
        )?;

        Ok(signed_tokens)
    }
}
