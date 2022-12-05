use crate::{
    traits::Verifiable,
    structs::{EncryptedUserId, ModeratorSignature, PublicKeys},
};
use serde::Serialize;

#[derive(Serialize)]
pub struct ModeratorToken {
    /// Encryption of user id
    pub x_1: EncryptedUserId,
    /// Ephemeral public signing key
    pub epk: Vec<u8>,
    pub sig: ModeratorSignature,
}

impl Verifiable for ModeratorToken {
    fn verify(&self, keys: PublicKeys) -> bool {
        // TODO verify moderator signature
        // somehow need to get the moderator key material??
    }
}
