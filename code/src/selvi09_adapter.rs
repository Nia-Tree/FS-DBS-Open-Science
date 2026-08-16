//! Unified benchmark adapter for Selvi et al. ePrint 2008/341, Section 2.5.

use crate::{
    common::encode_indices,
    scheme_adapter::{
        CiphertextStorage, FeatureSupport, KeyPair, SchemeAdapter, SchemeCapabilities, SchemeError,
        SecretKeyStorage, SetupParameters,
    },
    selvi09::{Ciphertext, IdentityKey, IdentityPublicKey, Selvi09},
};
use rand::RngCore;

#[derive(Clone)]
pub struct Selvi09PublicKey {
    pub index: usize,
    pub inner: IdentityPublicKey,
}

#[derive(Clone)]
pub struct Selvi09SecretKey {
    pub index: usize,
    pub inner: IdentityKey,
}

pub struct Selvi09Adapter {
    scheme: Selvi09,
}

impl SchemeAdapter for Selvi09Adapter {
    type PublicKey = Selvi09PublicKey;
    type SecretKey = Selvi09SecretKey;
    type Ciphertext = Ciphertext;

    fn scheme_name() -> &'static str {
        "Selvi09"
    }

    fn capabilities() -> SchemeCapabilities {
        SchemeCapabilities {
            distributed_keygen: FeatureSupport::No,
            forward_security: FeatureSupport::No,
            broadcast_encryption: FeatureSupport::Yes,
            sender_authentication: FeatureSupport::Yes,
            signcryption: FeatureSupport::Yes,
            // The paper's games fix the challenge receiver set at the outset.
            ind_cca: FeatureSupport::Yes,
            euf_cma: FeatureSupport::Yes,
            constant_ciphertext: FeatureSupport::Yes,
            key_update: FeatureSupport::NotApplicable,
        }
    }

    fn setup<R: RngCore>(parameters: SetupParameters, rng: &mut R) -> Result<Self, SchemeError> {
        if parameters.max_users == 0 {
            return Err(SchemeError::InvalidInput(
                "Selvi09 requires at least one receiver slot".to_owned(),
            ));
        }
        Ok(Self {
            scheme: Selvi09::setup(parameters.max_users, rng),
        })
    }

    fn keygen<R: RngCore>(
        &self,
        identity: usize,
        _rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        let identity_bytes = format!("edge-{identity}").into_bytes();
        let inner = self.scheme.extract(&identity_bytes);
        Ok(KeyPair {
            public: Selvi09PublicKey {
                index: identity,
                inner: inner.public.clone(),
            },
            secret: Selvi09SecretKey {
                index: identity,
                inner,
            },
        })
    }

    fn signcrypt<R: RngCore>(
        &self,
        sender_secret: &Self::SecretKey,
        sender_public: &Self::PublicKey,
        recipients: &[usize],
        public_keys: &[Self::PublicKey],
        message: &[u8; 32],
        rng: &mut R,
    ) -> Result<Self::Ciphertext, SchemeError> {
        validate_sender(sender_secret, sender_public)?;
        let selected = select_public_keys(recipients, public_keys)?;
        // The timed operation includes the paper's product-polynomial
        // construction and public-parameter evaluation used to form y.
        let cache = self.scheme.prepare_encrypt_recipients(&selected);
        Ok(self
            .scheme
            .signcrypt_cached(&sender_secret.inner, &cache, message, rng))
    }

    fn unsigncrypt(
        &self,
        receiver: usize,
        receiver_secret: &Self::SecretKey,
        sender_public: &Self::PublicKey,
        recipients: &[usize],
        public_keys: &[Self::PublicKey],
        ciphertext: &Self::Ciphertext,
    ) -> Result<[u8; 32], SchemeError> {
        if receiver_secret.index != receiver {
            return Err(SchemeError::InvalidInput(
                "Selvi09 receiver secret key does not match the requested slot".to_owned(),
            ));
        }
        let receiver_position = recipients
            .iter()
            .position(|slot| *slot == receiver)
            .ok_or_else(|| {
                SchemeError::InvalidInput("receiver is not in the Selvi09 target set".to_owned())
            })?;
        let selected = select_public_keys(recipients, public_keys)?;
        let cache = self.scheme.prepare_receiver(&selected, receiver_position);
        self.scheme
            .designcrypt_cached(
                receiver_position,
                &receiver_secret.inner,
                &sender_public.inner,
                &cache,
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
        // Section 2.5 transmits L but explicitly excludes set identification
        // from its constant-size cryptographic header claim.
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
            serialized_bytes: secret_key.inner.serialized_bytes().len(),
            number_of_g1_elements: 1,
            number_of_g2_elements: 0,
            number_of_zp_elements: 0,
        })
    }
}

fn validate_sender(
    secret: &Selvi09SecretKey,
    public: &Selvi09PublicKey,
) -> Result<(), SchemeError> {
    if secret.index != public.index || secret.inner.public.identity != public.inner.identity {
        return Err(SchemeError::InvalidInput(
            "Selvi09 sender public and private material do not match".to_owned(),
        ));
    }
    Ok(())
}

fn select_public_keys(
    recipients: &[usize],
    public_keys: &[Selvi09PublicKey],
) -> Result<Vec<IdentityPublicKey>, SchemeError> {
    if recipients.is_empty() {
        return Err(SchemeError::InvalidInput(
            "Selvi09 requires a nonempty receiver set".to_owned(),
        ));
    }
    recipients
        .iter()
        .map(|&slot| {
            let key = slot.checked_sub(1).and_then(|index| public_keys.get(index));
            match key {
                Some(key) if key.index == slot => Some(key.inner.clone()),
                _ => None,
            }
            .ok_or_else(|| {
                SchemeError::InvalidInput(
                    "Selvi09 recipients must be registered one-based slots".to_owned(),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn adapter_round_trip_and_real_serialization() {
        let mut rng = StdRng::seed_from_u64(2008_0341);
        let adapter = Selvi09Adapter::setup(
            SetupParameters {
                max_users: 16,
                tree_depth: 0,
            },
            &mut rng,
        )
        .unwrap();
        let users = (1..=17)
            .map(|identity| adapter.keygen(identity, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let public = users[..16]
            .iter()
            .map(|user| user.public.clone())
            .collect::<Vec<_>>();
        let recipients = [1usize, 4, 7, 11, 16];
        let ciphertext = adapter
            .signcrypt(
                &users[16].secret,
                &users[16].public,
                &recipients,
                &public,
                &[9u8; 32],
                &mut rng,
            )
            .unwrap();
        assert_eq!(
            adapter
                .unsigncrypt(
                    7,
                    &users[6].secret,
                    &users[16].public,
                    &recipients,
                    &public,
                    &ciphertext,
                )
                .unwrap(),
            [9u8; 32]
        );
        let storage = adapter
            .serialize_ciphertext(&ciphertext, &recipients)
            .unwrap();
        assert_eq!(storage.cryptographic_ciphertext_bytes, 224);
        assert_eq!(storage.recipient_metadata_bytes, recipients.len() * 8);
        assert_eq!(
            adapter
                .serialize_secret_key(&users[6].secret)
                .unwrap()
                .serialized_bytes,
            48
        );
    }
}
