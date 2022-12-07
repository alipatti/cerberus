use cerberus::roles::moderator::run_server;

/// Runs the moderator server in its own process.
#[allow(unused_must_use)]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let server = run_server();

    // Server will yield control of the thread once it gets up and the async block will run
    tokio::try_join!(server, async {
        println!("Server up!");
        Ok(())
    })?;

    Ok(())
}
