//! Benchmark adapter for Lee 2025 Section 4.1 `DBE_SS`.

use crate::{
    common::encode_indices,
    lee25::{Lee25Ss, Lee25SsCiphertext, Lee25SsPublicKey, Lee25SsSecretKey},
    scheme_adapter::{
        CiphertextStorage, FeatureSupport, KeyPair, SchemeAdapter, SchemeCapabilities, SchemeError,
        SecretKeyStorage, SetupParameters,
    },
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::cell::RefCell;

pub struct Lee25SsAdapter {
    scheme: Lee25Ss,
    decapsulation_rng: RefCell<StdRng>,
}

impl Lee25SsAdapter {
    pub fn is_valid<R: RngCore>(&self, public_key: &Lee25SsPublicKey, rng: &mut R) -> bool {
        self.scheme.is_valid(public_key, rng)
    }
}

impl SchemeAdapter for Lee25SsAdapter {
    type PublicKey = Lee25SsPublicKey;
    type SecretKey = Lee25SsSecretKey;
    type Ciphertext = Lee25SsCiphertext;

    fn scheme_name() -> &'static str {
        "Lee25-SS"
    }

    fn capabilities() -> SchemeCapabilities {
        SchemeCapabilities {
            distributed_keygen: FeatureSupport::Yes,
            forward_security: FeatureSupport::No,
            broadcast_encryption: FeatureSupport::Yes,
            sender_authentication: FeatureSupport::No,
            signcryption: FeatureSupport::No,
            ind_cca: FeatureSupport::Yes,
            euf_cma: FeatureSupport::NotApplicable,
            constant_ciphertext: FeatureSupport::Yes,
            key_update: FeatureSupport::NotApplicable,
        }
    }

    fn setup<R: RngCore>(parameters: SetupParameters, rng: &mut R) -> Result<Self, SchemeError> {
        if parameters.max_users == 0 {
            return Err(SchemeError::InvalidInput(
                "Lee25-SS requires at least one user slot".to_owned(),
            ));
        }
        let decapsulation_seed = rng.next_u64() ^ 0x1EE2_5DEC_A001;
        Ok(Self {
            scheme: Lee25Ss::setup(parameters.max_users, rng),
            decapsulation_rng: RefCell::new(StdRng::seed_from_u64(decapsulation_seed)),
        })
    }

    fn keygen<R: RngCore>(
        &self,
        identity: usize,
        rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        let (public, secret) = self.scheme.keygen(identity, rng);
        Ok(KeyPair { public, secret })
    }

    fn join<R: RngCore>(
        &self,
        identity: usize,
        rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        self.keygen(identity, rng)
    }

    fn encrypt<R: RngCore>(
        &self,
        recipients: &[usize],
        public_keys: &[Self::PublicKey],
        message: &[u8; 32],
        rng: &mut R,
    ) -> Result<Self::Ciphertext, SchemeError> {
        validate_slots(recipients, public_keys)?;
        Ok(self
            .scheme
            .encaps(recipients, public_keys, b"", message, rng))
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
        if receiver_secret.index != receiver || !recipients.contains(&receiver) {
            return Err(SchemeError::InvalidInput(
                "receiver is not authorized for this Lee25-SS ciphertext".to_owned(),
            ));
        }
        self.scheme
            .decaps(
                recipients,
                receiver_secret,
                public_keys,
                ciphertext,
                b"",
                &mut *self.decapsulation_rng.borrow_mut(),
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
            number_of_g1_elements: 1,
            number_of_g2_elements: 0,
            number_of_zp_elements: 0,
        })
    }
}

fn validate_slots(
    recipients: &[usize],
    public_keys: &[Lee25SsPublicKey],
) -> Result<(), SchemeError> {
    if recipients.is_empty()
        || recipients.iter().any(|&slot| {
            slot == 0 || slot > public_keys.len() || public_keys[slot - 1].index != slot
        })
    {
        return Err(SchemeError::InvalidInput(
            "Lee25-SS recipients must be registered one-based slots".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_round_trip_and_real_serialization() {
        let mut rng = StdRng::seed_from_u64(0x1EE2_5002);
        let adapter = Lee25SsAdapter::setup(
            SetupParameters {
                max_users: 16,
                tree_depth: 0,
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
        let recipients = [1usize, 4, 7, 11, 16];
        let message = [0x25; 32];
        let ciphertext = adapter
            .encrypt(&recipients, &public_keys, &message, &mut rng)
            .unwrap();
        assert_eq!(
            adapter
                .decrypt(7, &users[6].secret, &recipients, &public_keys, &ciphertext,)
                .unwrap(),
            message
        );
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
                .serialized_bytes,
            56
        );
    }
}


// Fixture preparation only; original online methods and decapsulation RNG remain unchanged.
impl Lee25SsAdapter {
    pub fn quick_receiver_fixture_keygen(
        &self, identity: usize, receiver: usize, rng: &mut rand::rngs::StdRng,
    ) -> KeyPair<Lee25SsPublicKey, Lee25SsSecretKey> {
        let mut validation_rng = rng.clone();
        let (public, secret) = self.scheme.quick_receiver_fixture_keygen(identity, receiver, rng);
        self.scheme.advance_fixture_validation_rng(rng);
        if identity == 2 {
            let (full_public, full_secret) = self.scheme.keygen(identity, &mut validation_rng);
            assert!(self.scheme.is_valid(&full_public, &mut validation_rng), "complete Lee key must pass IsValid");
            self.scheme.assert_quick_fixture_fields_equal(
                &public, &secret, &full_public, &full_secret, receiver,
            );
            let mut projected_next = rng.clone();
            assert_eq!(
                rand::RngCore::next_u64(&mut projected_next),
                rand::RngCore::next_u64(&mut validation_rng),
                "Lee fixture must preserve keygen plus IsValid RNG consumption",
            );
        }
        KeyPair { public, secret }
    }
}
