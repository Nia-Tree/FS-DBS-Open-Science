//! Unified benchmark adapter for KMW23 Section 5.1 / Construction A.7.

use crate::{
    common::encode_indices,
    kmw23::{Ciphertext, Kmw23, UserPublicKey, UserSecretKey},
    scheme_adapter::{
        CiphertextStorage, FeatureSupport, KeyPair, SchemeAdapter, SchemeCapabilities, SchemeError,
        SecretKeyStorage, SetupParameters,
    },
};
use rand::RngCore;

pub struct Kmw23Adapter {
    scheme: Kmw23,
}

impl SchemeAdapter for Kmw23Adapter {
    type PublicKey = UserPublicKey;
    type SecretKey = UserSecretKey;
    type Ciphertext = Ciphertext;

    fn scheme_name() -> &'static str {
        "KMW23"
    }

    fn capabilities() -> SchemeCapabilities {
        SchemeCapabilities {
            distributed_keygen: FeatureSupport::Yes,
            forward_security: FeatureSupport::No,
            broadcast_encryption: FeatureSupport::Yes,
            sender_authentication: FeatureSupport::No,
            signcryption: FeatureSupport::No,
            ind_cca: FeatureSupport::No,
            euf_cma: FeatureSupport::NotApplicable,
            constant_ciphertext: FeatureSupport::Yes,
            key_update: FeatureSupport::NotApplicable,
        }
    }

    fn setup<R: RngCore>(parameters: SetupParameters, rng: &mut R) -> Result<Self, SchemeError> {
        if parameters.max_users == 0 {
            return Err(SchemeError::InvalidInput(
                "KMW23 requires at least one slot".to_owned(),
            ));
        }
        Ok(Self {
            scheme: Kmw23::setup(parameters.max_users, rng),
        })
    }

    fn keygen<R: RngCore>(
        &self,
        identity: usize,
        rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        let user = self.scheme.keygen(identity, rng);
        Ok(KeyPair {
            public: user.public,
            secret: user.secret,
        })
    }

    fn encrypt<R: RngCore>(
        &self,
        recipients: &[usize],
        public_keys: &[Self::PublicKey],
        message: &[u8; 32],
        rng: &mut R,
    ) -> Result<Self::Ciphertext, SchemeError> {
        let cache = self
            .scheme
            .prepare_encrypt_recipients(recipients, public_keys);
        Ok(self.scheme.encrypt_cached(&cache, message, rng))
    }

    fn decrypt(
        &self,
        receiver: usize,
        receiver_secret: &Self::SecretKey,
        recipients: &[usize],
        public_keys: &[Self::PublicKey],
        ciphertext: &Self::Ciphertext,
    ) -> Result<[u8; 32], SchemeError> {
        if !recipients.contains(&receiver) || receiver_secret.index != receiver {
            return Err(SchemeError::InvalidInput(
                "receiver is not authorized for this KMW23 ciphertext".to_owned(),
            ));
        }
        let mut cache = self.scheme.prepare_receiver_recipients(recipients);
        self.scheme
            .add_receiver_context(&mut cache, receiver, public_keys, receiver_secret);
        self.scheme
            .decrypt_cached(receiver, &cache, ciphertext)
            .ok_or(SchemeError::AuthenticationFailed)
    }

    fn serialize_ciphertext(
        &self,
        ciphertext: &Self::Ciphertext,
        recipients: &[usize],
    ) -> Result<CiphertextStorage, SchemeError> {
        let cryptographic = ciphertext.serialized_bytes().len();
        let metadata = encode_indices(recipients).len();
        Ok(CiphertextStorage {
            cryptographic_ciphertext_bytes: cryptographic,
            recipient_metadata_bytes: metadata,
            total_wire_bytes: cryptographic + metadata,
        })
    }

    fn serialize_secret_key(
        &self,
        secret_key: &Self::SecretKey,
    ) -> Result<SecretKeyStorage, SchemeError> {
        Ok(SecretKeyStorage {
            serialized_bytes: secret_key.serialized_bytes().len(),
            number_of_g1_elements: 1,
            number_of_g2_elements: 0,
            number_of_zp_elements: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme_adapter::SchemeError;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn adapter_round_trip_and_real_serialization() {
        let mut rng = StdRng::seed_from_u64(2307);
        let adapter = Kmw23Adapter::setup(
            SetupParameters {
                max_users: 16,
                tree_depth: 4,
            },
            &mut rng,
        )
        .unwrap();
        let users = (1..=16)
            .map(|identity| adapter.keygen(identity, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let public = users
            .iter()
            .map(|user| user.public.clone())
            .collect::<Vec<_>>();
        let recipients = [1usize, 4, 7, 9, 16];
        let message = [0x23u8; 32];
        let ciphertext = adapter
            .encrypt(&recipients, &public, &message, &mut rng)
            .unwrap();
        assert_eq!(
            adapter
                .decrypt(7, &users[6].secret, &recipients, &public, &ciphertext,)
                .unwrap(),
            message
        );
        let storage = adapter
            .serialize_ciphertext(&ciphertext, &recipients)
            .unwrap();
        assert_eq!(storage.cryptographic_ciphertext_bytes, 176);
        assert_eq!(storage.recipient_metadata_bytes, recipients.len() * 8);
        assert!(matches!(
            adapter.join(1, &mut rng),
            Err(SchemeError::Unsupported { .. })
        ));
    }
}
