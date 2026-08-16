//! Unified benchmark adapter for Gao et al., Information Sciences 690 (2025).

use crate::{
    gao25::{Ciphertext, Gao25, PublicKey, User},
    scheme_adapter::{
        CiphertextStorage, FeatureSupport, KeyPair, SchemeAdapter, SchemeCapabilities, SchemeError,
        SecretKeyStorage, SetupParameters,
    },
};
use rand::RngCore;

#[derive(Clone)]
pub struct Gao25PublicKey {
    pub index: usize,
    pub inner: PublicKey,
}

#[derive(Clone)]
pub struct Gao25SecretKey {
    pub index: usize,
    pub inner: User,
}

pub struct Gao25Adapter {
    scheme: Gao25,
}

impl SchemeAdapter for Gao25Adapter {
    type PublicKey = Gao25PublicKey;
    type SecretKey = Gao25SecretKey;
    type Ciphertext = Ciphertext;

    fn scheme_name() -> &'static str {
        "Gao25"
    }

    fn capabilities() -> SchemeCapabilities {
        SchemeCapabilities {
            // The user samples its secret value; the authority issues only a
            // certificate, so the construction has no key-escrow master key.
            distributed_keygen: FeatureSupport::Yes,
            forward_security: FeatureSupport::No,
            broadcast_encryption: FeatureSupport::Yes,
            sender_authentication: FeatureSupport::Yes,
            signcryption: FeatureSupport::Yes,
            ind_cca: FeatureSupport::Yes,
            euf_cma: FeatureSupport::Yes,
            constant_ciphertext: FeatureSupport::No,
            key_update: FeatureSupport::NotApplicable,
        }
    }

    fn setup<R: RngCore>(parameters: SetupParameters, rng: &mut R) -> Result<Self, SchemeError> {
        if parameters.max_users == 0 {
            return Err(SchemeError::InvalidInput(
                "Gao25 requires at least one receiver slot".to_owned(),
            ));
        }
        Ok(Self {
            scheme: Gao25::setup(parameters.max_users, rng),
        })
    }

    fn join<R: RngCore>(
        &self,
        identity: usize,
        rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        let identity_bytes = format!("edge-{identity}").into_bytes();
        let inner = self.scheme.register(&identity_bytes, rng);
        Ok(KeyPair {
            public: Gao25PublicKey {
                index: identity,
                inner: inner.public.clone(),
            },
            secret: Gao25SecretKey {
                index: identity,
                inner,
            },
        })
    }

    fn keygen<R: RngCore>(
        &self,
        identity: usize,
        rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        self.join(identity, rng)
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
        if sender_secret.index != sender_public.index {
            return Err(SchemeError::InvalidInput(
                "Gao25 sender public and private material do not match".to_owned(),
            ));
        }
        let selected = select_public_keys(recipients, public_keys)?;
        // The full source Signcrypt is timed, including H1/H2 evaluation,
        // Lagrange polynomial construction, and coefficient interpolation.
        Ok(self
            .scheme
            .signcrypt(&sender_secret.inner, &selected, message, rng))
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
        if receiver_secret.index != receiver || !recipients.contains(&receiver) {
            return Err(SchemeError::InvalidInput(
                "receiver is not authorized for this Gao25 ciphertext".to_owned(),
            ));
        }
        select_public_keys(recipients, public_keys)?;
        self.scheme
            .unsigncrypt(&receiver_secret.inner, &sender_public.inner, ciphertext)
            .ok_or(SchemeError::AuthenticationFailed)
    }

    fn serialize_ciphertext(
        &self,
        ciphertext: &Self::Ciphertext,
        _recipients: &[usize],
    ) -> Result<CiphertextStorage, SchemeError> {
        let cryptographic = ciphertext.serialized_bytes().len();
        // The Section 4 ciphertext carries n+1 interpolation coefficients and
        // no explicit receiver identities.
        Ok(CiphertextStorage {
            cryptographic_ciphertext_bytes: cryptographic,
            recipient_metadata_bytes: 0,
            total_wire_bytes: cryptographic,
        })
    }

    fn serialize_secret_key(
        &self,
        secret_key: &Self::SecretKey,
    ) -> Result<SecretKeyStorage, SchemeError> {
        Ok(SecretKeyStorage {
            serialized_bytes: secret_key.inner.serialized_bytes().len(),
            number_of_g1_elements: 0,
            number_of_g2_elements: 0,
            number_of_zp_elements: 2,
        })
    }
}

fn select_public_keys(
    recipients: &[usize],
    public_keys: &[Gao25PublicKey],
) -> Result<Vec<PublicKey>, SchemeError> {
    if recipients.is_empty() {
        return Err(SchemeError::InvalidInput(
            "Gao25 requires a nonempty receiver set".to_owned(),
        ));
    }
    recipients
        .iter()
        .map(|&slot| {
            let key = slot.checked_sub(1).and_then(|index| public_keys.get(index));
            match key {
                Some(key) if key.index == slot => Ok(key.inner.clone()),
                _ => Err(SchemeError::InvalidInput(
                    "Gao25 recipients must be registered one-based slots".to_owned(),
                )),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn adapter_round_trip_and_linear_ciphertext_size() {
        let mut rng = StdRng::seed_from_u64(121_540);
        let adapter = Gao25Adapter::setup(
            SetupParameters {
                max_users: 16,
                tree_depth: 0,
            },
            &mut rng,
        )
        .unwrap();
        let users = (1..=17)
            .map(|identity| adapter.join(identity, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let public = users[..16]
            .iter()
            .map(|user| user.public.clone())
            .collect::<Vec<_>>();
        let recipients = [1usize, 4, 7, 11, 16];
        let message = [0x25u8; 32];
        let ciphertext = adapter
            .signcrypt(
                &users[16].secret,
                &users[16].public,
                &recipients,
                &public,
                &message,
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
            message
        );
        let storage = adapter
            .serialize_ciphertext(&ciphertext, &recipients)
            .unwrap();
        assert_eq!(
            storage.cryptographic_ciphertext_bytes,
            33 * recipients.len() + 130
        );
        assert_eq!(storage.recipient_metadata_bytes, 0);
        assert_eq!(
            adapter
                .serialize_secret_key(&users[6].secret)
                .unwrap()
                .serialized_bytes,
            64
        );
    }
}
