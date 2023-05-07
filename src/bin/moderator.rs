fn main() -> cerberus::Result<()> {
    let server = tiny_http::Server::http("0.0.0.0:80").unwrap();

    loop {
        cerberus::Moderator::run_server(&server)?;
    }
}
