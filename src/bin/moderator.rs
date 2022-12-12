use cerberus::roles::moderator::run_server;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    run_server()
}
