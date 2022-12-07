use actix_web::{dev::Server, middleware::Logger, App, HttpServer};
use std::io;

pub async fn run_server() -> io::Result<Server> {
    // TODO add HTTPS
    Ok(HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(endpoints::healthcheck)
            .service(endpoints::signing)
    })
    .bind("0.0.0.0:80")? // listen on default http port
    .run())
}

mod endpoints {
    use crate::communication as coms;
    use actix_web::{get, web};

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

    // #[get("/setup")]
    // pub(super) async fn setup(
    //     request: web::Json<coms::setup::Request>,
    // ) -> web::Json<coms::setup::Response> {
    //     web::Json(coms::setup::Response {
    //         hello: "world".into(),
    //     })
    // }

    /// Endpoint queried by coordinator to get signatures
    #[get("/")]
    pub(super) async fn signing(
        request: web::Json<coms::signing::Request>,
    ) -> web::Json<coms::signing::Response> {
        println!("{request:?}");

        web::Json(coms::signing::Response {
            hello: "world".into(),
        })
    }
}
