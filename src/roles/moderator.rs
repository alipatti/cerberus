use actix_web::{dev::Server, middleware::Logger, web, App, HttpServer};
use frost::round1::{SigningCommitments, SigningNonces};
use frost_ristretto255 as frost;
use rand::rngs::ThreadRng;
use std::{io, sync::Mutex};

pub async fn run_server() -> io::Result<Server> {
    // TODO add HTTPS

    let state: ServerState = web::Data::new(Mutex::new(None));

    Ok(HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            .service(endpoints::healthcheck)
            .service(endpoints::sign)
    })
    .bind("0.0.0.0:80")? // listen on default http port
    .run())
}

struct Moderator {
    frost_key_package: frost::keys::KeyPackage,
    // rng: ThreadRng,
}

// CHECK do we need to use a mutex here?
type ServerState = web::Data<Mutex<Option<Moderator>>>;

impl Moderator {
    pub fn generate_nonce_batch(&self) -> (SigningNonces, SigningCommitments) {
        let mut rng = ThreadRng::default();
        frost::round1::commit(
            self.frost_key_package.identifier,
            &self.frost_key_package.secret_share,
            &mut rng,
        )
    }
}

mod endpoints {
    use super::{Moderator, ServerState};
    use crate::communication as coms;
    use actix_web::{get, web, HttpResponse, Responder};
    use frost_ristretto255 as frost;
    use std::error::Error;

    /// Endpoint to test whether the server is functioning.
    #[get("/healthcheck")]
    pub(super) async fn healthcheck(
        request: web::Json<coms::healthcheck::Request>,
    ) -> web::Json<coms::healthcheck::Response> {
        println!("Received message: {request:#?}");

        web::Json(coms::healthcheck::Response {
            message: "Hello from a moderator!".into(),
        })
    }

    #[get("/setup")]
    pub(super) async fn setup(
        request: web::Json<coms::setup::Request>,
        state: ServerState,
    ) -> Result<impl Responder, Box<dyn Error>> {
        // extract key package
        let key_package =
            frost::keys::KeyPackage::try_from(request.0.secret_share)?;

        // acquire mutex lock
        let mut moderator = state.lock().unwrap(); // CHECK will this ever panic?

        if let Some(_) = *moderator {
            return Ok(HttpResponse::TooManyRequests()
                .body("Setup may only be queried once."));
        }

        // set moderator value
        *moderator = Some(Moderator {
            frost_key_package: key_package,
        });

        // TODO generate a batch of nonces, store the nonces, and send back their commitments

        let response = coms::setup::Response {
            hello: "world".into(),
        };

        Ok(HttpResponse::Ok().json(response))
    }

    /// Endpoint queried by coordinator to get signatures
    #[get("/sign")]
    pub(super) async fn sign(
        request: web::Json<coms::signing::Request>,
    ) -> web::Json<coms::signing::Response> {
        println!("{request:?}");

        // check that signing keys are defined

        web::Json(coms::signing::Response {
            hello: "world".into(),
        })
    }

    #[get("/decrypt")]
    pub(super) async fn decrypt() -> impl Responder {
        HttpResponse::NotImplemented()
    }
}
