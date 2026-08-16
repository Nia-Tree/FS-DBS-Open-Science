//! Benchmark adapter for Zhang et al. 2023 DAAGKAwSNP.

use crate::{
    scheme_adapter::{
        CiphertextStorage, FeatureSupport, KeyPair, SchemeAdapter, SchemeCapabilities, SchemeError,
        SecretKeyStorage, SetupParameters,
    },
    zhang23::{
        AgreementContribution, Ciphertext, GroupContext, GroupEpoch, IdentityPublicKey,
        IdentitySecretKey, Zhang23,
    },
};
use rand::RngCore;

#[derive(Clone)]
pub struct Zhang23PublicKey {
    pub index: usize,
    pub inner: IdentityPublicKey,
}

#[derive(Clone)]
pub struct Zhang23SecretKey {
    pub index: usize,
    pub inner: IdentitySecretKey,
}

pub struct Zhang23Adapter {
    scheme: Zhang23,
}

impl Zhang23Adapter {
    pub fn prepare_epoch<R: RngCore>(
        &self,
        recipients: &[usize],
        secret_keys: &[Zhang23SecretKey],
        rng: &mut R,
    ) -> Result<GroupEpoch, SchemeError> {
        let selected = select_secret_keys(recipients, secret_keys)?;
        self.scheme
            .agree_group(&selected, rng)
            .ok_or_else(|| SchemeError::InvalidInput("Zhang23 agreement failed".to_owned()))
    }

    pub fn create_local_agreement_contribution<R: RngCore>(
        &self,
        member: &Zhang23SecretKey,
        rng: &mut R,
    ) -> AgreementContribution {
        self.scheme
            .create_agreement_contribution(&member.inner, rng)
    }

    pub fn derive_local_receiver_context(
        &self,
        epoch: &GroupEpoch,
        receiver: usize,
    ) -> Result<GroupContext, SchemeError> {
        self.scheme
            .derive_receiver_context(epoch, receiver)
            .ok_or_else(|| {
                SchemeError::InvalidInput("Zhang23 receiver key derivation failed".to_owned())
            })
    }

    pub fn prepare_all_receivers<R: RngCore>(
        &self,
        recipients: &[usize],
        secret_keys: &[Zhang23SecretKey],
        rng: &mut R,
    ) -> Result<Vec<GroupContext>, SchemeError> {
        let epoch = self.prepare_epoch(recipients, secret_keys, rng)?;
        recipients
            .iter()
            .map(|&receiver| self.derive_local_receiver_context(&epoch, receiver))
            .collect()
    }

    pub fn prepare_group<R: RngCore>(
        &self,
        recipients: &[usize],
        secret_keys: &[Zhang23SecretKey],
        receiver: usize,
        rng: &mut R,
    ) -> Result<GroupContext, SchemeError> {
        let selected = select_secret_keys(recipients, secret_keys)?;
        self.scheme
            .prepare_group(&selected, receiver, rng)
            .ok_or_else(|| SchemeError::InvalidInput("Zhang23 group preparation failed".to_owned()))
    }

    pub fn signcrypt_prepared<R: RngCore>(
        &self,
        sender_secret: &Zhang23SecretKey,
        sender_public: &Zhang23PublicKey,
        group: &GroupContext,
        message: &[u8; 32],
        rng: &mut R,
    ) -> Result<Ciphertext, SchemeError> {
        validate_sender(sender_secret, sender_public)?;
        Ok(self
            .scheme
            .sign_encrypt(&sender_secret.inner, group, message, rng))
    }

    pub fn unsigncrypt_prepared(
        &self,
        receiver: usize,
        receiver_secret: &Zhang23SecretKey,
        sender_public: &Zhang23PublicKey,
        group: &GroupContext,
        ciphertext: &Ciphertext,
    ) -> Result<[u8; 32], SchemeError> {
        if receiver_secret.index != receiver {
            return Err(SchemeError::InvalidInput(
                "Zhang23 receiver key does not match the selected member".to_owned(),
            ));
        }
        self.scheme
            .decrypt_verify(receiver, &sender_public.inner, group, ciphertext)
            .ok_or(SchemeError::AuthenticationFailed)
    }
}

impl SchemeAdapter for Zhang23Adapter {
    type PublicKey = Zhang23PublicKey;
    type SecretKey = Zhang23SecretKey;
    type Ciphertext = Ciphertext;

    fn scheme_name() -> &'static str {
        "Zhang23-DAAGKA"
    }

    fn capabilities() -> SchemeCapabilities {
        SchemeCapabilities {
            distributed_keygen: FeatureSupport::Yes,
            forward_security: FeatureSupport::No,
            broadcast_encryption: FeatureSupport::Yes,
            sender_authentication: FeatureSupport::Yes,
            signcryption: FeatureSupport::Yes,
            ind_cca: FeatureSupport::Yes,
            euf_cma: FeatureSupport::Yes,
            constant_ciphertext: FeatureSupport::Yes,
            key_update: FeatureSupport::NotApplicable,
        }
    }

    fn setup<R: RngCore>(_parameters: SetupParameters, _rng: &mut R) -> Result<Self, SchemeError> {
        Ok(Self {
            scheme: Zhang23::setup(),
        })
    }

    fn keygen<R: RngCore>(
        &self,
        identity: usize,
        rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        let inner = self.scheme.keygen(identity, rng);
        Ok(KeyPair {
            public: Zhang23PublicKey {
                index: identity,
                inner: inner.public.clone(),
            },
            secret: Zhang23SecretKey {
                index: identity,
                inner,
            },
        })
    }

    fn serialize_ciphertext(
        &self,
        ciphertext: &Self::Ciphertext,
        _recipients: &[usize],
    ) -> Result<CiphertextStorage, SchemeError> {
        let cryptographic = ciphertext.serialized_bytes().len();
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
            number_of_zp_elements: 1,
        })
    }
}

fn validate_sender(
    secret: &Zhang23SecretKey,
    public: &Zhang23PublicKey,
) -> Result<(), SchemeError> {
    if secret.index != public.index || secret.inner.public.index != public.inner.index {
        return Err(SchemeError::InvalidInput(
            "Zhang23 sender public and private keys do not match".to_owned(),
        ));
    }
    Ok(())
}

fn select_secret_keys(
    recipients: &[usize],
    secret_keys: &[Zhang23SecretKey],
) -> Result<Vec<IdentitySecretKey>, SchemeError> {
    if recipients.is_empty() {
        return Err(SchemeError::InvalidInput(
            "Zhang23 requires a nonempty established group".to_owned(),
        ));
    }
    recipients
        .iter()
        .map(|slot| {
            slot.checked_sub(1)
                .and_then(|index| secret_keys.get(index))
                .filter(|key| key.index == *slot)
                .map(|key| key.inner.clone())
                .ok_or_else(|| {
                    SchemeError::InvalidInput(
                        "Zhang23 recipients must be registered one-based slots".to_owned(),
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
    fn prepared_adapter_round_trip() {
        let mut rng = StdRng::seed_from_u64(23);
        let adapter = Zhang23Adapter::setup(
            SetupParameters {
                max_users: 16,
                tree_depth: 0,
            },
            &mut rng,
        )
        .unwrap();
        let users = (1..=9)
            .map(|index| adapter.keygen(index, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let secrets = users[..8]
            .iter()
            .map(|user| user.secret.clone())
            .collect::<Vec<_>>();
        let recipients = (1..=8).collect::<Vec<_>>();
        let group = adapter
            .prepare_group(&recipients, &secrets, 1, &mut rng)
            .unwrap();
        let ciphertext = adapter
            .signcrypt_prepared(
                &users[8].secret,
                &users[8].public,
                &group,
                &[8u8; 32],
                &mut rng,
            )
            .unwrap();
        assert_eq!(
            adapter
                .unsigncrypt_prepared(1, &users[0].secret, &users[8].public, &group, &ciphertext,)
                .unwrap(),
            [8u8; 32]
        );
        assert_eq!(
            adapter
                .serialize_ciphertext(&ciphertext, &recipients)
                .unwrap()
                .cryptographic_ciphertext_bytes,
            272
        );

        let all_groups = adapter
            .prepare_all_receivers(&recipients, &secrets, &mut rng)
            .unwrap();
        assert_eq!(all_groups.len(), recipients.len());
        let epoch_ciphertext = adapter
            .signcrypt_prepared(
                &users[8].secret,
                &users[8].public,
                &all_groups[0],
                &[10u8; 32],
                &mut rng,
            )
            .unwrap();
        for (offset, group) in all_groups.iter().enumerate() {
            assert_eq!(
                adapter
                    .unsigncrypt_prepared(
                        offset + 1,
                        &users[offset].secret,
                        &users[8].public,
                        group,
                        &epoch_ciphertext,
                    )
                    .unwrap(),
                [10u8; 32]
            );
        }
    }
}
