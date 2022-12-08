// TODO Get rid of actix web here and use a single-threaded framework

use crate::token::UnsignedToken;
use crate::{parameters::BATCH_SIZE, Batch};
use actix_web::{dev::Server, middleware::Logger, web, App, HttpServer};
use frost::{
    round1::{SigningCommitments, SigningNonces},
    round2::{SignatureShare, SigningPackage},
};
use frost_ristretto255 as frost;
use rand::rngs::ThreadRng;
use std::error::Error;
use std::{io, sync::Mutex};

pub async fn run_server() -> io::Result<Server> {
    // TODO add HTTPS

    let state: ServerState = web::Data::new(Mutex::new(None));

    Ok(HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            .service(endpoints::ping)
            .service(endpoints::sign)
    })
    .bind("0.0.0.0:80")? // listen on default http port
    .workers(1)
    .run())
}

struct Moderator {
    frost_key_package: frost::keys::KeyPackage,

    /// The next batch of nonces to use
    ///
    /// These MUST be kept in sync with the commitment values sent to the coordinator.
    nonces: Batch<SigningNonces>,
}

type ServerState = web::Data<Mutex<Option<Moderator>>>;

impl Moderator {
    pub fn init(
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

    /// Signs a new batch of tokens
    ///
    /// Internally, this method also updates the stored nonces and returns a new batch of commitments.
    pub fn sign_batch(
        &mut self,
        signing_packages: &Batch<SigningPackage>,
    ) -> Result<
        (Batch<SignatureShare>, Batch<SigningCommitments>),
        Box<dyn Error>,
    > {
        let signatures = array_init::try_array_init(|i| {
            let signing_package = &signing_packages[i];
            let token_to_sign: UnsignedToken =
                bincode::deserialize(signing_package.message())?;

            // TODO somehow verify the token

            let signature_share = frost::round2::sign(
                signing_package,
                &self.nonces[i],
                &self.frost_key_package,
            )?;

            // awkward type hinting
            Ok::<_, Box<dyn Error>>(signature_share)
        })?;

        let (new_nonces, new_commitments) =
            Moderator::generate_nonces(&self.frost_key_package);
        self.nonces = new_nonces;

        Ok((signatures, new_commitments))
    }

    // not a &self method because it's called by init
    fn generate_nonces(
        frost_key_package: &frost::keys::KeyPackage,
    ) -> (Batch<SigningNonces>, Batch<SigningCommitments>) {
        // TODO port to array-init
        let mut rng = ThreadRng::default();

        // allocate vectors
        let (mut nonces, mut coms) = (
            Vec::with_capacity(BATCH_SIZE),
            Vec::with_capacity(BATCH_SIZE),
        );

        // fill vectors
        for _ in 0..BATCH_SIZE {
            let (nonce, com) = frost::round1::commit(
                frost_key_package.identifier,
                &frost_key_package.secret_share,
                &mut rng,
            );
            nonces.push(nonce);
            coms.push(com);
        }

        // cast vectors into array
        // hacky unwrap because FROST doesn't implement debug
        (
            nonces.try_into().unwrap_or_else(|_| panic!()),
            coms.try_into().unwrap_or_else(|_| panic!()),
        )
    }
}

mod endpoints {
    use std::ops::{Deref, DerefMut};

    use super::{Moderator, ServerState};
    use crate::communication as coms;
    use actix_web::{get, web, HttpResponse, Responder};
    use frost_ristretto255 as frost;

    /// Endpoint to test whether the server is functioning.
    #[get("/ping")]
    pub(super) async fn ping() -> impl Responder {
        println!("Server online");
        HttpResponse::Ok()
    }

    /// Endpoint queried to setup the moderator server.
    ///
    /// Internally, this method validates the secret share send by the coordinator and stores
    /// the extracted key package for future use.
    /// It then generates a batch of nonces and sends their commitments back to
    /// the moderator to be used in the next round of token-signing.
    #[get("/setup")]
    pub(super) async fn setup(
        request: web::Json<coms::setup::Request>,
        state: ServerState,
    ) -> HttpResponse {
        // validate share and extract key package
        let key_package =
            match frost::keys::KeyPackage::try_from(request.0.secret_share) {
                Ok(package) => package,
                Err(_) => {
                    return HttpResponse::BadRequest()
                        .body("Invalid secret share.")
                }
            };

        // acquire mutex lock
        let mut state = state.lock().unwrap(); // CHECK will this ever panic?

        if (*state).is_some() {
            return HttpResponse::TooManyRequests()
                .body("Setup may only be queried once.");
        }

        let (moderator, nonce_commitments) = Moderator::init(key_package);

        let response = coms::setup::Response { nonce_commitments };

        // update the state
        *state = Some(moderator);

        HttpResponse::Ok().json(response)
    }

    /// Endpoint queried by coordinator to get signatures
    #[get("/sign")]
    pub(super) async fn sign(
        request: web::Json<coms::signing::Request>,
        state: ServerState,
    ) -> HttpResponse {
        // acquire mutex lock
        let mut state = state.lock().unwrap(); // CHECK will this ever panic?
        let moderator = match state.deref_mut() {
            Some(moderator) => moderator,
            None => {
                return HttpResponse::Forbidden()
                    .body("/setup must be queried before /sign")
            }
        };

        moderator.sign_batch(&request.signing_packages);

        unimplemented!()
    }

    #[get("/decrypt")]
    pub(super) async fn decrypt() -> impl Responder {
        HttpResponse::NotImplemented()
    }
}
