//! Benchmark adapter for AFI06 `C(BasicHICBE2)`.

use crate::{
    afi06::{Afi06, Ciphertext, ForwardSecureState},
    common::encode_indices,
    scheme_adapter::{
        CiphertextStorage, FeatureSupport, KeyPair, SchemeAdapter, SchemeCapabilities, SchemeError,
        SecretKeyStorage, SetupParameters,
    },
};
use rand::RngCore;

#[derive(Clone)]
pub struct Afi06PublicKey {
    pub index: usize,
}

pub struct Afi06Adapter {
    scheme: Afi06,
}

impl SchemeAdapter for Afi06Adapter {
    type PublicKey = Afi06PublicKey;
    type SecretKey = ForwardSecureState;
    type Ciphertext = Ciphertext;

    fn scheme_name() -> &'static str {
        "AFI06"
    }

    fn capabilities() -> SchemeCapabilities {
        SchemeCapabilities {
            distributed_keygen: FeatureSupport::No,
            forward_security: FeatureSupport::Yes,
            broadcast_encryption: FeatureSupport::Yes,
            sender_authentication: FeatureSupport::No,
            signcryption: FeatureSupport::No,
            ind_cca: FeatureSupport::No,
            euf_cma: FeatureSupport::NotApplicable,
            constant_ciphertext: FeatureSupport::Yes,
            key_update: FeatureSupport::Yes,
        }
    }

    fn setup<R: RngCore>(parameters: SetupParameters, rng: &mut R) -> Result<Self, SchemeError> {
        if parameters.max_users <= parameters.tree_depth {
            return Err(SchemeError::InvalidInput(
                "AFI06 BasicHICBE2 requires max_users > tree_depth".to_owned(),
            ));
        }
        Ok(Self {
            scheme: Afi06::setup(parameters.max_users, parameters.tree_depth, rng),
        })
    }

    fn keygen<R: RngCore>(
        &self,
        identity: usize,
        rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        Ok(KeyPair {
            public: Afi06PublicKey { index: identity },
            secret: self.scheme.initial_state(identity, rng),
        })
    }

    fn join<R: RngCore>(
        &self,
        identity: usize,
        rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        self.keygen(identity, rng)
    }

    fn update<R: RngCore>(
        &self,
        secret_key: &Self::SecretKey,
        _child_bit: u8,
        rng: &mut R,
    ) -> Result<Self::SecretKey, SchemeError> {
        self.scheme
            .update_state(secret_key, rng)
            .ok_or_else(|| SchemeError::InvalidInput("AFI06 time tree is exhausted".to_owned()))
    }

    fn encrypt<R: RngCore>(
        &self,
        recipients: &[usize],
        public_keys: &[Self::PublicKey],
        message: &[u8; 32],
        rng: &mut R,
    ) -> Result<Self::Ciphertext, SchemeError> {
        validate_slots(recipients, public_keys)?;
        let recipient_cache = self.scheme.prepare_encrypt_recipients(recipients);
        let time = self.scheme.prepare_time(&[]);
        Ok(self
            .scheme
            .encrypt_cached(&recipient_cache, &time, message, rng))
    }

    fn decrypt(
        &self,
        receiver: usize,
        receiver_secret: &Self::SecretKey,
        recipients: &[usize],
        public_keys: &[Self::PublicKey],
        ciphertext: &Self::Ciphertext,
    ) -> Result<[u8; 32], SchemeError> {
        validate_slots(recipients, public_keys)?;
        if !recipients.contains(&receiver) || receiver_secret.current().index != receiver {
            return Err(SchemeError::InvalidInput(
                "receiver is not authorized for this AFI06 ciphertext".to_owned(),
            ));
        }
        let time = self.scheme.prepare_time(&[]);
        let mut recipient_cache = self.scheme.prepare_receiver_recipients(recipients);
        self.scheme
            .add_receiver_context(&mut recipient_cache, receiver, receiver_secret.current());
        self.scheme
            .decrypt_cached(
                receiver,
                receiver_secret.current(),
                &recipient_cache,
                &time,
                ciphertext,
            )
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
            number_of_g1_elements: 0,
            number_of_g2_elements: secret_key.number_of_g2_elements(),
            number_of_zp_elements: 0,
        })
    }
}

fn validate_slots(recipients: &[usize], public_keys: &[Afi06PublicKey]) -> Result<(), SchemeError> {
    if recipients.is_empty()
        || recipients.iter().any(|&slot| {
            slot == 0 || slot > public_keys.len() || public_keys[slot - 1].index != slot
        })
    {
        return Err(SchemeError::InvalidInput(
            "AFI06 recipients must be registered one-based slots".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn adapter_round_trip_update_and_serialization() {
        let mut rng = StdRng::seed_from_u64(0xAF10_6002);
        let adapter = Afi06Adapter::setup(
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
        let public_keys = users
            .iter()
            .map(|user| user.public.clone())
            .collect::<Vec<_>>();
        let recipients = [1usize, 3, 7, 16];
        let message = [0xA6; 32];
        let ciphertext = adapter
            .encrypt(&recipients, &public_keys, &message, &mut rng)
            .unwrap();
        assert_eq!(
            adapter
                .decrypt(7, &users[6].secret, &recipients, &public_keys, &ciphertext,)
                .unwrap(),
            message
        );

        let advanced = adapter.update(&users[6].secret, 0, &mut rng).unwrap();
        assert!(matches!(
            adapter.decrypt(7, &advanced, &recipients, &public_keys, &ciphertext),
            Err(SchemeError::AuthenticationFailed)
        ));
        assert_eq!(
            adapter
                .serialize_ciphertext(&ciphertext, &recipients)
                .unwrap()
                .cryptographic_ciphertext_bytes,
            176
        );
        assert_eq!(
            adapter
                .serialize_secret_key(&users[6].secret)
                .unwrap()
                .number_of_g2_elements,
            6
        );
    }
}
