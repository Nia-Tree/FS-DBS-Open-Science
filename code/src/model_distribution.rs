//! Application-layer primitives for the ResNet-50 distribution experiment.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};

pub fn encrypt_model(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 keys contain 32 bytes");
    let nonce = Nonce::try_from(nonce.as_slice()).expect("GCM nonces contain 12 bytes");
    cipher.encrypt(
        &nonce,
        Payload {
            msg: plaintext,
            aad: associated_data,
        },
    )
}

pub fn decrypt_model(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 keys contain 32 bytes");
    let nonce = Nonce::try_from(nonce.as_slice()).expect("GCM nonces contain 12 bytes");
    cipher.decrypt(
        &nonce,
        Payload {
            msg: ciphertext,
            aad: associated_data,
        },
    )
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn update_manifest(
    model_id: &[u8],
    period: u64,
    receiver_set_id: &[u8; 32],
    encrypted_model_hash: &[u8; 32],
    cryptographic_header_hash: &[u8; 32],
) -> Vec<u8> {
    let mut manifest = Vec::with_capacity(model_id.len() + 112);
    manifest.extend_from_slice(b"FS-DBS/model-update-manifest/v1");
    manifest.extend_from_slice(&(model_id.len() as u64).to_le_bytes());
    manifest.extend_from_slice(model_id);
    manifest.extend_from_slice(&period.to_le_bytes());
    manifest.extend_from_slice(receiver_set_id);
    manifest.extend_from_slice(encrypted_model_hash);
    manifest.extend_from_slice(cryptographic_header_hash);
    manifest
}

pub fn nonce_from_counter(counter: u128) -> [u8; 12] {
    let encoded = counter.to_be_bytes();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&encoded[4..]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    #[test]
    fn aes_gcm_round_trip_binds_associated_data() {
        let key = [7u8; 32];
        let nonce = nonce_from_counter(1);
        let plaintext = b"in-memory model bytes";
        let ciphertext = encrypt_model(&key, &nonce, plaintext, b"model-v1").unwrap();
        assert_eq!(
            decrypt_model(&key, &nonce, &ciphertext, b"model-v1").unwrap(),
            plaintext
        );
        assert!(decrypt_model(&key, &nonce, &ciphertext, b"model-v2").is_err());
    }

    #[test]
    fn ed25519_authenticates_the_complete_update_manifest() {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let manifest = update_manifest(b"resnet50", 5, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let signature = signer.sign(&manifest);
        assert!(signer.verifying_key().verify(&manifest, &signature).is_ok());

        let mut modified = manifest;
        modified[0] ^= 1;
        assert!(signer
            .verifying_key()
            .verify(&modified, &signature)
            .is_err());
    }
}
