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
use rand::rngs::ThreadRng;

pub struct Moderator {
    // key material
    signing_keys: frost::keys::KeyPackage,
    encryption_keys: elgamal::KeyShare,

    /// The next batch of nonces to use
    ///
    /// These MUST be kept in sync with the commitment values sent to the coordinator.
    nonces: Batch<SigningNonces>,
}

impl Moderator {
    pub fn run_server() -> Result<()> {
        let server = tiny_http::Server::http("0.0.0.0:80").unwrap();

        // wait for setup request and handle it.
        let request = server.recv()?;
        let mut moderator = Self::new_from_setup_request(request)?;

        // continuously process signing requests
        loop {
            let request = server.recv()?;
            moderator.handle_signing_request(request)?;
        }
    }

    fn new_from_setup_request(
        mut request: tiny_http::Request,
    ) -> Result<Moderator> {
        println!("Received setup request from coordinator.");
        let body: communication::setup::Request =
            bincode::deserialize_from(request.as_reader())?;
        let frost_key_package =
            frost::keys::KeyPackage::try_from(body.frost_secret_share)?;
        let (moderator, nonce_commitments) =
            Moderator::new(frost_key_package, body.elgamal_secret_share);
        request.respond({
            let body = communication::setup::Response { nonce_commitments };
            let bytes = bincode::serialize(&body)?;

            tiny_http::Response::from_data(bytes)
        })?;
        Ok(moderator)
    }

    fn handle_signing_request(
        &mut self,
        mut request: tiny_http::Request,
    ) -> Result<()> {
        println!("Received token request from coordinator.");
        let body: communication::signing::Request = {
            let mut bytes = Vec::new();
            let bytes_len = request.as_reader().read_to_end(&mut bytes)?;
            assert_eq!(request.body_length().unwrap(), bytes_len);
            bincode::deserialize(&bytes)?
        };
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
                signing_keys,
                nonces,
                encryption_keys,
            },
            commitments,
        )
    }

    /// Signs a new batch of tokens. This method also internally updates the stored nonces and returns a new batch of commitments.
    pub(crate) fn sign_batch(
        &mut self,
        signing_requests: &Batch<SigningRequest>,
    ) -> Result<(Batch<SignatureShare>, Batch<SigningCommitments>)> {
        //  create signatures
        let signatures = try_array_init(|i| {
            self.process_signing_request(&signing_requests[i], &self.nonces[i])
        })?;

        // create new nonces
        let (new_nonces, new_commitments) =
            Moderator::generate_nonces(&self.signing_keys);

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
            &self.signing_keys,
        )
        // deal with special frost error type
        .map_err(|_| "Failed to create signature share".into())
    }

    fn verify_signing_request(
        &self,
        signing_request: &SigningRequest,
    ) -> Result<()> {
        // check that the thing being signed really is an encryption of the id being claimed.
        let deserialized_token: UnsignedToken = {
            let bytes = signing_request.signing_package.message();
            bincode::deserialize(bytes)
                    .map_err::<Box<dyn Error>, _>(|_| "Failed to deserialize unsigned token in moderator signing request.".into())?
        };

        let encryption_matches = {
            let encryption_claimed = deserialized_token.encryption_of_id;
            let encryption_calculated =
                self.encryption_keys.group_public.encrypt(
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
        let mut rng = ThreadRng::default();

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
        // hacky unwrap because FROST struct isn't Debug
        (
            nonces.try_into().unwrap_or_else(|_| panic!()),
            commitments.try_into().unwrap_or_else(|_| panic!()),
        )
    }
}
