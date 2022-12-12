use crate::communication;
use crate::token::UnsignedToken;
use crate::{parameters::BATCH_SIZE, Batch};
use frost::{
    round1::{SigningCommitments, SigningNonces},
    round2::{SignatureShare, SigningPackage},
};
use frost_ristretto255 as frost;
use rand::rngs::ThreadRng;
use std::error::Error;

pub fn run_server() -> Result<(), Box<dyn Error>> {
    let server = tiny_http::Server::http("0.0.0.0:0").unwrap();

    // TODO add HTTPS

    // -------------------------
    //           SETUP
    // -------------------------

    // wait for the coordinator to send setup information
    let mut request = server.recv()?;
    let body: communication::setup::Request =
        bincode::deserialize_from(request.as_reader())?;

    // verify secret share and unwrap key package
    let frost_key_package =
        frost::keys::KeyPackage::try_from(body.secret_share)?;
    let (mut moderator, nonce_commitments) = Moderator::init(frost_key_package);

    // send response
    let response = {
        let body = communication::setup::Response { nonce_commitments };
        let bytes = bincode::serialize(&body)?;
        tiny_http::Response::from_data(bytes)
    };
    request.respond(response)?; // send

    // ---------------------------
    //           SIGNING
    // ---------------------------

    // continuously process signing requests
    loop {
        // receive and deserialize request
        let mut request = server.recv().unwrap();
        let body: communication::signing::Request =
            bincode::deserialize_from(request.as_reader())?;

        // do the signing
        let (signature_shares, new_nonce_commitments) =
            moderator.sign_batch(&body.signing_packages)?;

        // send response
        let response = {
            let body = communication::signing::Response {
                signature_shares,
                new_nonce_commitments,
            };
            let bytes = bincode::serialize(&body)?;
            tiny_http::Response::from_data(bytes)
        };
        request.respond(response)?; // send
    }
}

struct Moderator {
    frost_key_package: frost::keys::KeyPackage,

    /// The next batch of nonces to use
    ///
    /// These MUST be kept in sync with the commitment values sent to the coordinator.
    nonces: Batch<SigningNonces>,
}

impl Moderator {
    fn init(
        frost_key_package: frost::keys::KeyPackage,
    ) -> (Self, Batch<SigningCommitments>) {
        let (nonces, commitments) =
            Moderator::generate_nonces(&frost_key_package);

        (
            Self {
                frost_key_package,
                nonces,
            },
            commitments,
        )
    }

    /// Signs a new batch of tokens. This method also internally updates the stored nonces and returns a new batch of commitments.
    fn sign_batch(
        &mut self,
        signing_packages: &Batch<SigningPackage>,
    ) -> Result<
        (Batch<SignatureShare>, Batch<SigningCommitments>),
        Box<dyn Error>,
    > {
        //  create signatures
        let signatures = array_init::try_array_init(|i| {
            let signing_package = &signing_packages[i];

            // TODO somehow verify the token
            let _token_to_sign: UnsignedToken =
                bincode::deserialize(signing_package.message())?;

            let signature_share = frost::round2::sign(
                signing_package,
                &self.nonces[i],
                &self.frost_key_package,
            )?;

            // awkward type hinting
            Ok::<_, Box<dyn Error>>(signature_share)
        })?;

        // create new nonces
        let (new_nonces, new_commitments) =
            Moderator::generate_nonces(&self.frost_key_package);

        // store the secrets, and return the new commitments alongside the signatures
        self.nonces = new_nonces;
        Ok((signatures, new_commitments))
    }

    // not a &self method because it's called by init
    fn generate_nonces(
        frost_key_package: &frost::keys::KeyPackage,
    ) -> (Batch<SigningNonces>, Batch<SigningCommitments>) {
        let mut rng = ThreadRng::default();

        // allocate vectors
        let mut nonces = Vec::with_capacity(BATCH_SIZE);
        let mut commitments = Vec::with_capacity(BATCH_SIZE);

        // fill vectors
        for _ in 0..BATCH_SIZE {
            let (nonce, commitment) = frost::round1::commit(
                frost_key_package.identifier,
                &frost_key_package.secret_share,
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
