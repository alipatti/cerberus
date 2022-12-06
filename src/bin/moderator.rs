use std::io;

use actix_web::{get, middleware::Logger, web, App, HttpServer};
use cerberus::communication;

/// Endpoint to test whether the server is functioning.
#[get("/healthcheck")]
async fn healthcheck(
    request: web::Json<communication::healthcheck::Request>,
) -> web::Json<communication::healthcheck::Response> {
    println!("Received message: {request:#?}");
    web::Json(communication::healthcheck::Response {
        message: "Hello from a moderator!".into(),
    })
}

/// Endpoint queried by coordinator repeatedly during normal operation.
#[get("/")]
async fn index(
    request: web::Json<communication::signing::Request>,
) -> web::Json<communication::signing::Response> {
    println!("{request:?}");

    web::Json(communication::signing::Response {
        hello: "world".into(),
    })
}

#[actix_web::main]
#[allow(unused_must_use)]
async fn main() -> io::Result<()> {
    let server = HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(healthcheck)
            .service(index)
    })
    .bind("0.0.0.0:80")?
    .run();

    tokio::join!(server, async { println!("Server up!") });

    Ok(())
}
