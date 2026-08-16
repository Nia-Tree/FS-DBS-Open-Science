//! Unified benchmark adapter for the paper's FS-DBS construction.

use crate::{
    fs_dbs::{Ciphertext, EvolvingKey, FsDbs, UserPublicKey},
    scheme_adapter::{
        CiphertextStorage, FeatureSupport, KeyPair, SchemeAdapter, SchemeCapabilities, SchemeError,
        SecretKeyStorage, SetupParameters,
    },
};
use rand::RngCore;

pub struct FsDbsAdapter {
    scheme: FsDbs,
}

impl FsDbsAdapter {
    /// Exposes the audited construction for benchmarks that separate
    /// set/period preparation from the online signcryption path.
    pub fn scheme(&self) -> &FsDbs {
        &self.scheme
    }

    pub fn projected_public_key_for_benchmark<R: RngCore>(
        &self,
        identity: usize,
        receiver: usize,
        rng: &mut R,
    ) -> UserPublicKey {
        self.scheme
            .join_public_projection_for_benchmark(identity, receiver, rng)
    }
}

impl SchemeAdapter for FsDbsAdapter {
    type PublicKey = UserPublicKey;
    type SecretKey = EvolvingKey;
    type Ciphertext = Ciphertext;

    fn scheme_name() -> &'static str {
        "FS-DBS"
    }

    fn capabilities() -> SchemeCapabilities {
        SchemeCapabilities {
            distributed_keygen: FeatureSupport::Yes,
            forward_security: FeatureSupport::Yes,
            broadcast_encryption: FeatureSupport::Yes,
            sender_authentication: FeatureSupport::Yes,
            signcryption: FeatureSupport::Yes,
            ind_cca: FeatureSupport::ToVerify,
            euf_cma: FeatureSupport::ToVerify,
            constant_ciphertext: FeatureSupport::Yes,
            key_update: FeatureSupport::Yes,
        }
    }

    fn setup<R: RngCore>(parameters: SetupParameters, rng: &mut R) -> Result<Self, SchemeError> {
        if parameters.max_users <= parameters.tree_depth {
            return Err(SchemeError::InvalidInput(
                "FS-DBS requires max_users > tree_depth".to_owned(),
            ));
        }
        Ok(Self {
            scheme: FsDbs::setup(parameters.max_users, parameters.tree_depth, rng),
        })
    }

    fn join<R: RngCore>(
        &self,
        identity: usize,
        rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        let user = self.scheme.join(identity, rng);
        Ok(KeyPair {
            public: user.public,
            secret: user.key,
        })
    }

    fn update<R: RngCore>(
        &self,
        secret_key: &Self::SecretKey,
        child_bit: u8,
        rng: &mut R,
    ) -> Result<Self::SecretKey, SchemeError> {
        if child_bit > 1 {
            return Err(SchemeError::InvalidInput(
                "child bit must be 0 or 1".to_owned(),
            ));
        }
        Ok(self.scheme.update_key(secret_key, child_bit, rng))
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
        let recipient_cache = self
            .scheme
            .prepare_encrypt_recipients(recipients, public_keys);
        let time_cache = self.scheme.prepare_time(&sender_secret.node);
        Ok(self.scheme.signcrypt_cached(
            sender_secret,
            sender_public,
            &recipient_cache,
            &time_cache,
            message,
            rng,
        ))
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
        if !recipients.contains(&receiver) {
            return Err(SchemeError::InvalidInput(
                "receiver is not in the authorized set".to_owned(),
            ));
        }
        let mut recipient_cache = self.scheme.prepare_receiver_recipients(recipients);
        self.scheme.add_receiver_context(
            &mut recipient_cache,
            receiver,
            public_keys,
            receiver_secret,
        );
        let time_cache = self.scheme.prepare_time(&receiver_secret.node);
        self.scheme
            .unsigncrypt_cached(
                receiver,
                receiver_secret,
                sender_public,
                &recipient_cache,
                &time_cache,
                ciphertext,
            )
            .ok_or(SchemeError::AuthenticationFailed)
    }

    fn serialize_ciphertext(
        &self,
        ciphertext: &Self::Ciphertext,
        recipients: &[usize],
    ) -> Result<CiphertextStorage, SchemeError> {
        let (cryptographic, metadata, total) =
            self.scheme.ciphertext_storage(ciphertext, recipients);
        Ok(CiphertextStorage {
            cryptographic_ciphertext_bytes: cryptographic,
            recipient_metadata_bytes: metadata,
            total_wire_bytes: total,
        })
    }

    fn serialize_secret_key(
        &self,
        secret_key: &Self::SecretKey,
    ) -> Result<SecretKeyStorage, SchemeError> {
        let (g1, g2, zp) = secret_key.element_counts();
        Ok(SecretKeyStorage {
            serialized_bytes: secret_key.serialized_bytes().len(),
            number_of_g1_elements: g1,
            number_of_g2_elements: g2,
            number_of_zp_elements: zp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn adapter_round_trip_after_key_update() {
        let mut rng = StdRng::seed_from_u64(7001);
        let adapter = FsDbsAdapter::setup(
            SetupParameters {
                max_users: 16,
                tree_depth: 4,
            },
            &mut rng,
        )
        .unwrap();
        let mut users = (1..=8)
            .map(|identity| adapter.join(identity, &mut rng).unwrap())
            .collect::<Vec<_>>();
        for child_bit in [1u8, 0, 1] {
            for user in &mut users {
                user.secret = adapter.update(&user.secret, child_bit, &mut rng).unwrap();
            }
        }
        let public = users
            .iter()
            .map(|user| user.public.clone())
            .collect::<Vec<_>>();
        let recipients = [1usize, 3, 5, 7];
        let message = [0x5au8; 32];
        let ciphertext = adapter
            .signcrypt(
                &users[7].secret,
                &users[7].public,
                &recipients,
                &public,
                &message,
                &mut rng,
            )
            .unwrap();
        assert_eq!(
            adapter
                .unsigncrypt(
                    5,
                    &users[4].secret,
                    &users[7].public,
                    &recipients,
                    &public,
                    &ciphertext,
                )
                .unwrap(),
            message
        );
        let size = adapter
            .serialize_ciphertext(&ciphertext, &recipients)
            .unwrap();
        assert_eq!(size.recipient_metadata_bytes, recipients.len() * 8);
    }
}
