use crate::parameters::GlobalParameters;
use frost_ristretto255 as frost;
use futures::future;
use rand::rngs::ThreadRng;
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, error::Error, fmt::Debug};

pub struct Coordinator {
    params: GlobalParameters,
    client: reqwest::Client,
    rng: ThreadRng,
}

impl Coordinator {
    /// Creates a new
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Coordinator {
            params: GlobalParameters::load()
                .expect("Failed to load environment variables."),
            client: reqwest::Client::new(),
            rng: ThreadRng::default(),
        }
    }

    /// Sends a query to every moderator at the provided endpoint and with the provided body.
    ///
    /// Returns a vector of their responses or an error if something failed.
    pub async fn query_moderators<Req, Res>(
        &self,
        endpoint: &str,
        body: &Req,
    ) -> Result<Vec<Res>, Box<dyn Error>>
    where
        Req: Serialize + DeserializeOwned + Debug,
        Res: Serialize + DeserializeOwned + Debug,
    {
        future::try_join_all((1..=self.params.n_moderators).map(
            |i| async move {
                let url = format!("http://cerberus-moderator-{i}/{endpoint}");

                let response = self.client.get(&url).json(body).send().await?;

                // TODO check for non-2XX status

                let body: Res = response.json().await?;

                Ok(body)
            },
        ))
        .await
    }

    /// Distributes encryption and signing key shares to the moderators.
    ///
    /// In practice, this centralized share dealing can be replaced by a distributed key generation protocol such as [TODO fill this in].
    pub async fn setup(&mut self) -> Result<(), Box<dyn Error>> {
        let (secret_shares, public_keys) = frost::keys::keygen_with_dealer(
            self.params.n_moderators,
            self.params.signature_threshold,
            &mut self.rng,
        )?;

        let share = &secret_shares[0];
        share.value;
        share.identifier;
        // Scalar  share.commitment;

        // TODO somehow we need to serialize the secret shares to send them over HTTP to
        // FROST has internal support for this, but it's hidden in private methods
        //

        let key_packages: HashMap<frost::Identifier, frost::keys::KeyPackage> =
            secret_shares
                .into_iter()
                .map(|share| Ok((share.identifier, share.try_into()?)))
                .collect::<Result<_, frost::Error>>()?;

        Ok(())
    }
}
