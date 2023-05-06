use core::panic;
use std::error::Error;

use crate::{
    communication, communication::signing::SigningRequest, elgamal,
    parameters::BATCH_SIZE, token::UnsignedToken, Batch, Result,
};
use array_init::try_array_init;
use frost::{
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use frost_ristretto255 as frost;

pub struct Moderator {
    // key material
    sk_signing: frost::keys::KeyPackage,
    encryption_keys: elgamal::KeyShare,

    /// The next batch of nonces to use
    ///
    /// These MUST be kept in sync with the commitment values sent to the coordinator.
    nonces: Batch<SigningNonces>,
}

impl Moderator {
    /// Runs the Moderator's HTTP server.
    pub fn run_server() -> Result<()> {
        let server = tiny_http::Server::http("0.0.0.0:80").unwrap();

        // wait for setup request and handle it.
        let request = server.recv()?;
        assert_eq!(
            request.url(),
            "/setup",
            "First request to moderator was not a setup request"
        );
        let mut moderator = Self::new_from_setup_request(request)?;

        println!("Setup successful.");

        // continuously process signing and decryption requests from
        // the coordinator
        loop {
            let request = server.recv()?;
            match request.url() {
                "/signing" => moderator.handle_signing(request)?,
                "/decryption" => moderator.handle_decryption(request)?,
                other => println!("Invalid endpoint: {other}"),
            }
        }
    }

    /// Creates a new [`Moderator`] object from a [`communication::setup::Request`] sent by the [`Coordinator`].
    fn new_from_setup_request(
        mut request: tiny_http::Request,
    ) -> Result<Moderator> {
        // println!("Received setup request from coordinator.");

        // deserialize request body
        let body: communication::setup::Request =
            bincode::deserialize_from(request.as_reader())?;

        // unpack the FROST key package
        let frost_key_package =
            frost::keys::KeyPackage::try_from(body.frost_secret_share)?;

        // create `Moderator` object and the first batch of FROST nonce commitments
        let (moderator, nonce_commitments) =
            Moderator::new(frost_key_package, body.elgamal_secret_share);

        // send response back to coordinator
        request.respond({
            let body = communication::setup::Response { nonce_commitments };
            let bytes = bincode::serialize(&body)?;

            tiny_http::Response::from_data(bytes)
        })?;
        Ok(moderator)
    }

    /// Handles a signing request from the [`Coordinator`].
    ///
    /// Under the hood, this...
    /// TODO finish documentation
    fn handle_signing(
        &mut self,
        mut request: tiny_http::Request,
    ) -> Result<()> {
        // println!("Received token request from coordinator.");
        let body: communication::signing::Request =
            bincode::deserialize_from(request.as_reader())?;

        let (signature_shares, new_nonce_commitments) =
            self.sign_batch(&body.signing_requests)?;

        request.respond({
            let body = communication::signing::Response {
                signature_shares,
                new_nonce_commitments,
            };
            let bytes = bincode::serialize(&body)?;
            tiny_http::Response::from_data(bytes)
        })?;

        Ok(())
    }

    fn new(
        signing_keys: frost::keys::KeyPackage,
        encryption_keys: elgamal::KeyShare,
    ) -> (Self, Batch<SigningCommitments>) {
        let (nonces, commitments) = Moderator::generate_nonces(&signing_keys);

        (
            Self {
                sk_signing: signing_keys,
                nonces,
                encryption_keys,
            },
            commitments,
        )
    }

    /// Signs a new batch of tokens. This method also internally updates the stored nonces and returns a new batch of commitments.
    fn sign_batch(
        &mut self,
        signing_requests: &Batch<SigningRequest>,
    ) -> Result<(Batch<SignatureShare>, Batch<SigningCommitments>)> {
        //  create signatures
        let signatures = try_array_init(|i| {
            self.process_signing_request(&signing_requests[i], &self.nonces[i])
        })?;

        // create new nonces
        let (new_nonces, new_commitments) =
            Moderator::generate_nonces(&self.sk_signing);

        // store the secrets, and return the new commitments alongside the signatures
        self.nonces = new_nonces;
        Ok((signatures, new_commitments))
    }

    fn process_signing_request(
        &self,
        signing_request: &SigningRequest,
        nonces: &SigningNonces,
    ) -> Result<SignatureShare> {
        self.verify_signing_request(signing_request)?;
        self.sign_signing_request(signing_request, nonces)
    }

    fn sign_signing_request(
        &self,
        signing_request: &SigningRequest,
        nonces: &SigningNonces,
    ) -> Result<SignatureShare> {
        frost::round2::sign(
            &signing_request.signing_package,
            nonces,
            &self.sk_signing,
        )
        // deal with special frost error type
        .map_err(|_| "Failed to create signature share".into())
    }

    fn verify_signing_request(
        &self,
        signing_request: &SigningRequest,
    ) -> Result<()> {
        // check that the thing being signed really is an encryption of
        // the claimed UserId with the claimed randomness
        let deserialized_token: UnsignedToken = {
            let bytes = signing_request.signing_package.message();
            bincode::deserialize(bytes)
                    .map_err::<Box<dyn Error>, _>(
                        |_| "Failed to deserialize unsigned token in moderator signing request.".into())?
        };

        let encryption_matches = {
            let encryption_claimed = deserialized_token.x_1;
            let encryption_calculated = self.encryption_keys.encrypt(
                &signing_request.user_id,
                &signing_request.elgamal_randomness,
            );

            match encryption_calculated == encryption_claimed {
                true => Ok(()),
                false => {
                    Err("ID encryption doesn't match what is claimed.".into())
                }
            }
        };

        let timestamp_valid = Ok(()); // TODO

        encryption_matches.and(timestamp_valid)
    }

    // not a &self method because it's called by init
    fn generate_nonces(
        frost_keys: &frost::keys::KeyPackage,
    ) -> (Batch<SigningNonces>, Batch<SigningCommitments>) {
        let mut rng = rand::thread_rng();

        // allocate vectors
        let mut nonces = Vec::with_capacity(BATCH_SIZE);
        let mut commitments = Vec::with_capacity(BATCH_SIZE);

        // fill vectors
        for _ in 0..BATCH_SIZE {
            let (nonce, commitment) = frost::round1::commit(
                frost_keys.identifier,
                &frost_keys.secret_share,
                &mut rng,
            );
            nonces.push(nonce);
            commitments.push(commitment);
        }

        // cast vectors into array
        // requires a hacky unwrap because the FROST structs aren't Debug
        (
            nonces.try_into().unwrap_or_else(|_| panic!()),
            commitments.try_into().unwrap_or_else(|_| panic!()),
        )
    }

    fn handle_decryption(&self, mut request: tiny_http::Request) -> Result<()> {
        let body: communication::decryption::Request =
            bincode::deserialize_from(request.as_reader())?;

        // TODO: verify well-formed-ness of the report

        let decryption_share = self.encryption_keys.decryption_share(&body.x_1);

        request.respond({
            let body = communication::decryption::Response { decryption_share };
            let bytes = bincode::serialize(&body)?;
            tiny_http::Response::from_data(bytes)
        })?;

        Ok(())
    }
}
