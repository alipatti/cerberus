use actix_web::{get, post, web, App, HttpServer, Responder};
use cerberus::coordinator;

/// Endpoint to test whether the server is up.
///
/// Polled incrementally by the moderator to figure out when to run the setup.
#[get("/healthcheck")]
async fn healthcheck() -> &'static str {
    "Hello world!"
}

/// Endpoint to set the key material of a moderator.
#[post("/setup")]
async fn setup() -> impl Responder {
    unimplemented!();
    ""
}

/// Endpoint queried by coordinator repeatedly during normal operation.
#[get("/")]
async fn create_signature_share(
    request: web::Json<coordinator::http::Request>,
) -> web::Json<coordinator::http::Response> {

    println!("hello {}", request.hello);

    unimplemented!()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Hello moderator!");

    HttpServer::new(|| App::new().service(healthcheck))
        .bind(("127.0.0.1", 8))?
        .run()
        .await
}
