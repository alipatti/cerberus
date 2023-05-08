use std::error::Error;

use chrono::Utc;
use curve25519_dalek::scalar::Scalar;
use frost_ristretto255 as frost;
use futures::future;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    communication, elgamal,
    token::{SignedToken, UnsignedToken},
    Batch, Result, UserId,
};

/// Nonce commitments from from all the moderators. Good for ONE batch of token-signing.
/// Indexed like `commitments [moderator_index] [batch_index]`
type CommitmentBatch = Vec<Batch<frost::round1::SigningCommitments>>;

pub struct Coordinator {
    pub(crate) frost_public_key_package: frost::keys::PublicKeyPackage,
    pub(crate) group_public_elgamal_key: elgamal::PublicKey,
    client: reqwest::Client,

    nonce_commitments: CommitmentBatch,

    // parameters
    batch_size: usize,
    n_moderators: usize,
    decryption_threshold: usize,
    _signing_threshold: usize, // TODO: do we need this?
}

/// Enum representing whether or not the requests to each moderator
/// are Unique (one request per mod) or Same (the same request to each)
enum ModeratorRequest<'a, T> {
    Same(&'a T),
    Unique(&'a [T]),
}

/// A wrapper type around a vector storing moderator responses.
type ModeratorResponses<Res> = Vec<Res>;

impl Coordinator {
    /// Sets up the coordinator and moderators
    ///
    /// Returns a new coordinator object if successful.
    pub async fn init(
        n_moderators: usize,
        signing_threshold: usize,
        decryption_threshold: usize,
        batch_size: usize,
    ) -> Result<Self> {
        assert!(n_moderators >= signing_threshold);
        assert!(n_moderators >= decryption_threshold);
        assert!(batch_size >= 1);

        let client = reqwest::Client::new();

        let (
            frost_public_key_package,
            group_public_elgamal_key,
            nonce_commitments,
        ) = Self::setup_moderators(
            &client,
            batch_size,
            n_moderators,
            signing_threshold,
            decryption_threshold,
        )
        .await?;

        Ok(Coordinator {
            client,
            frost_public_key_package,
            group_public_elgamal_key,
            nonce_commitments,
            n_moderators,
            _signing_threshold: signing_threshold,
            decryption_threshold,
            batch_size,
        })
    }

    async fn setup_moderators(
        client: &reqwest::Client,
        batch_size: usize,
        n_moderators: usize,
        signing_threshold: usize,
        decryption_threshold: usize,
    ) -> Result<(
        frost::keys::PublicKeyPackage,
        elgamal::PublicKey,
        CommitmentBatch,
    )> {
        let mut rng = rand::thread_rng();

        let (frost_secret_shares, frost_public_key) =
            frost::keys::keygen_with_dealer(
                n_moderators as u16,
                signing_threshold as u16,
                &mut rng,
            )?;

        let (elgamal_public_key, elgamal_key_shares) =
            elgamal::generate_private_key_shares(
                &mut rng,
                n_moderators,
                decryption_threshold,
            );

        let mut request_bodies = Vec::with_capacity(n_moderators);
        request_bodies.extend((0..n_moderators).map(|i| {
            communication::setup::Request {
                frost_secret_share: frost_secret_shares[i].clone(),
                elgamal_secret_share: elgamal_key_shares[i].clone(),
                batch_size,
            }
        }));

        let responses = query_moderators::<_, communication::setup::Response>(
            client,
            "setup",
            ModeratorRequest::Unique(&request_bodies),
            n_moderators,
        )
        .await?;

        let nonce_commitments = responses
            .into_iter()
            .map(|response| response.nonce_commitments)
            .collect();

        Ok((frost_public_key, elgamal_public_key, nonce_commitments))
    }

    pub async fn create_tokens(
        &mut self,
        user_ids: &Batch<UserId>,
    ) -> Result<Batch<SignedToken>> {
        // create signing requests to sent to the moderators
        let signing_requests = self.create_signing_requests(user_ids);

        let request = communication::signing::Request {
            // FIX: this clone doesn't seem like it should be necessary...
            signing_requests: signing_requests.clone(),
        };

        // get signature shares from each moderator for all tokens in the batch
        let moderator_responses =
            query_moderators::<_, communication::signing::Response>(
                &self.client,
                "signing",
                ModeratorRequest::Same(&request),
                self.n_moderators,
            )
            .await?;

        // package the results as a SignedToken batch
        let mut signed_tokens = Vec::with_capacity(self.batch_size);

        for (i, signing_request) in signing_requests.into_iter().enumerate() {
            let signature_shares: Vec<_> = moderator_responses
                .iter()
                .map(|response| response.signature_shares[i])
                .collect();

            let token = bincode::deserialize(
                signing_request.signing_package.message(),
            )?;

            let signature = frost::aggregate(
                &signing_request.signing_package,
                &signature_shares,
                &self.frost_public_key_package,
            )?;

            signed_tokens.push(SignedToken { signature, token });
        }

        self.nonce_commitments = moderator_responses
            .into_iter()
            .map(|response| response.new_nonce_commitments)
            .collect();

        Ok(signed_tokens)
    }

    pub async fn request_token_decryption(
        &self,
        token: &SignedToken,
    ) -> Result<UserId> {
        let request = communication::decryption::Request {
            message: "hello world".as_bytes().to_owned(),
            x_1: token.token.x_1.clone(),
        };

        let responses =
            query_moderators::<_, communication::decryption::Response>(
                &self.client,
                "decryption",
                ModeratorRequest::Same(&request),
                self.n_moderators,
            )
            .await?;

        let decryption_shares: Vec<_> = responses
            .into_iter()
            .map(|response| response.decryption_share)
            .collect();

        token.token.x_1.decrypt_with_shares(
            &decryption_shares[..self.decryption_threshold],
        )
    }

    fn create_signing_requests(
        &self,
        user_ids: &Batch<UserId>,
    ) -> Batch<communication::signing::SigningRequest> {
        let mut rng = rand::thread_rng();

        let mut requests = Vec::with_capacity(self.batch_size);
        for (i, user_id) in user_ids.iter().enumerate() {
            let elgamal_randomness = Scalar::random(&mut rng);

            let signing_package = {
                // create unsigned token struct
                let token = UnsignedToken {
                    timestamp: Utc::now().timestamp(),
                    x_1: self
                        .group_public_elgamal_key
                        .encrypt(user_id, &elgamal_randomness),
                    pk_e: [0u8; 32], // TODO make this a real key
                };

                // serialize the token so it can be passed to frost::sign()
                let token_bytes = bincode::serialize(&token).unwrap();

                // collect the signing_commitments
                let signing_commitments = (0..self.n_moderators)
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

            requests.push(communication::signing::SigningRequest {
                signing_package,
                elgamal_randomness,
                user_id: user_id.to_owned(),
            })
        }

        requests
    }

    pub async fn shutdown_moderators(&self) -> Result<()> {
        future::try_join_all((1..=self.n_moderators).map(|i| async move {
            let url = format!("http://cerberus-moderator-{i}:80/shutdown");
            let response = self.client.get(&url).send().await?;

            if response.status() == 200 {
                Ok::<(), Box<dyn Error>>(())
            } else {
                Err(format!("Failed to shutdown moderator {i}").into())
            }
        }))
        .await?;

        Ok(())
    }
}

/// Sends a query to every moderator at the provided endpoint and with the provided body.
///
/// Returns an array of type [`Res`; [`N_MODERATORS`]]
async fn query_moderators<Req, Res>(
    client: &reqwest::Client,
    endpoint: &str,
    payload: ModeratorRequest<'_, Req>,
    n_moderators: usize,
) -> Result<ModeratorResponses<Res>>
where
    Req: Serialize + DeserializeOwned,
    Res: Serialize + DeserializeOwned,
{
    let payload = &payload;
    let responses =
        future::try_join_all((1..=n_moderators).map(|i| async move {
            let url = format!("http://cerberus-moderator-{i}:80/{endpoint}");
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
        .await?;

    Ok(responses)
}
