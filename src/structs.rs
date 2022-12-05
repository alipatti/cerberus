// /// User ID type.
// /// This gets encrypted inside the moderator token.
// pub type UserId = i32;

// pub mod token {
//     use crate::crypto::{ed25519, elgamal};
//     use serde::{Deserialize, Serialize};

//     #[derive(Deserialize, Serialize)]
//     pub struct Token {
//         /// Encryption of user id
//         pub x_1: elgamal::Ciphertext,

//         /// Ephemeral public signing key
//         pub epk: ed25519::PublicKey,

//         /// Moderator signature, serialized from FROST
//         pub signature: Vec<u8>,
//     }
// }

// pub trait Verifiable {
//     fn verify(&self, public_keys: PublicKeys) -> bool;
// }
