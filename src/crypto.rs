/// Module containing the crypto primitives used by Cerberus.

/// Used for moderator threshold encryption
pub mod elgamal {
    pub type PublicKey = ();
    pub type PublicShare = ();
    pub type SecretShare = ();
    pub type DecryptionShare = ();

    pub type Message = Vec<u8>;
    pub type Ciphertext = Vec<u8>;
}

/// Used for moderator threshold signatures
// pub mod frost {
//     pub type PublicKey = frost_ed25519::VerifyingKey;
//     pub type PublicShare = frost_ed25519::round2::SignatureShare;
//     pub type SecretShare = ();
//     pub type SignatureShare = ();

//     pub type Message = Vec<u8>;
//     pub type Signature = Vec<u8>;
// }

/// Used for ephemeral private keys.
pub mod ed25519 {
    pub type PublicKey = ();
    pub type SecretKey = ();

    pub type Message = Vec<u8>;
    pub type Ciphertext = Vec<u8>;
}
