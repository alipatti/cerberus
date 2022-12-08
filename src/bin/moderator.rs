use cerberus::roles::moderator::run_server;

/// Runs the moderator server in its own process.
#[allow(unused_must_use)]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let server = run_server();

    // server will yield control of the thread once it finishes its setup.
    // then the async block will run... at least i think
    tokio::try_join!(server, async {
        println!("Server up!");
        Ok(())
    })?;

    Ok(())
}
