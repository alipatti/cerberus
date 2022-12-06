/// Setup round of communication
pub mod healthcheck {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Request {
        pub message: String,
    }

    #[derive(Deserialize, Debug, Serialize)]
    pub struct Response {
        pub message: String,
    }
}

/// Setup round of communication
pub mod setup {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Request {
        pub hello: String,
    }

    #[derive(Deserialize, Debug, Serialize)]
    pub struct Response {
        pub hello: String,
    }
}

// Signing round of communication
pub mod signing {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Request {
        pub hello: String,
    }

    #[derive(Deserialize, Debug, Serialize)]
    pub struct Response {
        pub hello: String,
    }
}
