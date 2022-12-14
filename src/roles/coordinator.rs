use std::{error::Error, time::SystemTime};

use array_init::array_init;
use curve25519_dalek::scalar::Scalar;
use frost_ristretto255 as frost;
use futures::future;
use rand::rngs::ThreadRng;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    communication::{self as coms, signing::SigningRequest},
    elgamal,
    parameters::{N_MODERATORS, SIGNING_THRESHOLD},
    token::{SignedToken, UnsignedToken},
    Batch, Result, UserId,
};

/// Nonce commitments from from all the moderators. Good for ONE batch of token-signing.
/// Ordered like `nonce_commitments [moderator_index] [batch_index]`
type CommitmentBatch = [Batch<frost::round1::SigningCommitments>; N_MODERATORS];

pub struct Coordinator {
    pub(crate) frost_public_key_package: frost::keys::PublicKeyPackage,
    pub(crate) group_public_elgamal_key: elgamal::PublicKey,
    client: reqwest::Client,

    nonce_commitments: CommitmentBatch,
}

enum ModeratorRequest<'a, T> {
    Same(&'a T),
    Unique(&'a [T; N_MODERATORS]),
}

type ModeratorResponses<Res> = [Res; N_MODERATORS];

// TODO add documentation

impl Coordinator {
    /// Sets up the coordinator and moderators
    ///
    /// Returns a new coordinator object if successful.
    pub async fn init() -> Result<Self> {
        let client = reqwest::Client::new();

        let (
            frost_public_key_package,
            group_public_elgamal_key,
            nonce_commitments,
        ) = Self::setup_moderators(&client).await?;

        Ok(Coordinator {
            client,
            frost_public_key_package,
            group_public_elgamal_key,
            nonce_commitments,
        })
    }

    async fn setup_moderators(
        client: &reqwest::Client,
    ) -> Result<(
        frost::keys::PublicKeyPackage,
        elgamal::PublicKey,
        CommitmentBatch,
    )> {
        let mut rng = ThreadRng::default();

        let (frost_secret_shares, frost_public_key) =
            frost::keys::keygen_with_dealer(
                N_MODERATORS as u16,
                SIGNING_THRESHOLD as u16,
                &mut rng,
            )?;

        let (elgamal_public_key, elgamal_key_shares) = {
            let private_key = elgamal::PrivateKey::random();
            let shares = private_key.create_shares()?;
            let public_key: elgamal::PublicKey = (&private_key).into();

            (public_key, shares)
        };

        let request_bodies = array_init(|i| coms::setup::Request {
            frost_secret_share: frost_secret_shares[i].clone(),
            elgamal_secret_share: elgamal_key_shares[i].clone(),
        });

        let responses = Self::query_moderators::<_, coms::setup::Response>(
            client,
            ModeratorRequest::Unique(&request_bodies),
        )
        .await?;

        let nonce_commitments = array_init::from_iter(
            responses.iter().map(|response| response.nonce_commitments),
        )
        .expect("Not enough nonce commitments.");

        Ok((frost_public_key, elgamal_public_key, nonce_commitments))
    }
    /// Sends a query to every moderator at the provided endpoint and with the provided body.
    ///
    /// Returns an array of type [`Res`; [`N_MODERATORS`]]
    async fn query_moderators<Req, Res>(
        client: &reqwest::Client,
        payload: ModeratorRequest<'_, Req>,
    ) -> Result<ModeratorResponses<Res>>
    where
        Req: Serialize + DeserializeOwned,
        Res: Serialize + DeserializeOwned,
    {
        let payload = &payload;
        array_init::from_iter(
            future::try_join_all((1..=N_MODERATORS).map(|i| async move {
                let url = format!("http://cerberus-moderator-{i}:80/");
                let body = {
                    let body_struct = match payload {
                        ModeratorRequest::Same(body) => body,
                        ModeratorRequest::Unique(bodies) => &bodies[i - 1], // zero-indexed
                    };

                    bincode::serialize(body_struct)?
                };

                let response = client.get(&url).body(body).send().await?;

                // error on non-200 responses
                if response.status() != reqwest::StatusCode::OK {
                    return Err(format!(
                        "Received unsuccessful response from moderator {i}"
                    )
                    .into());
                }

                Ok::<Res, Box<dyn Error>>({
                    let bytes = response.bytes().await?;
                    let body: Res = bincode::deserialize(&bytes)?;

                    body
                })
            }))
            .await?,
        )
        .ok_or_else(|| "Failed to convert response vector into array".into())
    }

    pub async fn create_tokens(
        &self,
        user_ids: &Batch<UserId>,
    ) -> Result<Batch<SignedToken>> {
        // create signing requests to sent to the moderators
        let signing_requests = self.create_signing_requests(user_ids);
        let signing_requests_backup = signing_requests.clone();

        let request = coms::signing::Request { signing_requests };

        // get signature shares from each moderator for all tokens in the batch
        let moderator_responses =
            Self::query_moderators::<_, coms::signing::Response>(
                &self.client,
                ModeratorRequest::Same(&request),
            )
            .await?;

        // package the results as a SignedToken batch
        let signed_tokens: Batch<SignedToken> =
            array_init::try_array_init(|i| -> Result<SignedToken> {
                let signature_shares: Vec<_> = moderator_responses
                    .iter()
                    .map(|response| response.signature_shares[i])
                    .collect();

                let signing_package =
                    &signing_requests_backup[i].signing_package;
                let token = bincode::deserialize(signing_package.message())?;

                let signature = frost::aggregate(
                    signing_package,
                    &signature_shares,
                    &self.frost_public_key_package,
                )?;

                Ok(SignedToken { signature, token })
            })?;

        Ok(signed_tokens)
    }

    fn create_signing_requests(
        &self,
        user_ids: &Batch<UserId>,
    ) -> Batch<SigningRequest> {
        let mut rng = ThreadRng::default();

        array_init(|i| {
            let elgamal_randomness = Scalar::random(&mut rng);
            let user_id = user_ids[i];

            let signing_package = {
                // create unsigned token struct
                let token = UnsignedToken {
                    timestamp: SystemTime::now(),
                    encryption_of_id: self
                        .group_public_elgamal_key
                        .encrypt(&user_id, &elgamal_randomness),
                    pk_e: [0u8; 32], // TODO make this a real key
                };

                // serialize the token so it can be passed to frost::sign()
                let token_bytes = bincode::serialize(&token).unwrap();

                // collect the signing_commitments
                let signing_commitments = (0..N_MODERATORS)
                    .map(|moderator_index| {
                        self.nonce_commitments[moderator_index][i]
                    })
                    .collect();

                // create the signing package
                frost::round2::SigningPackage::new(
                    signing_commitments,
                    token_bytes,
                )
            };

            SigningRequest {
                signing_package,
                elgamal_randomness,
                user_id,
            }
        })
    }
}
