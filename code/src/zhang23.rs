//! Zhang et al. 2023 DAAGKAwSNP, Section 5.2.
//!
//! This implementation adapts the earlier `DAAGA2.rs` prototype to the common
//! BLS12-381 backend. For a full active group, the paper's vacant-slot `R_i`
//! and `c_{i,j}` terms disappear. Ciphertext points remain in G1; agreement
//! contributions, member decryption keys, and signatures are placed in G2.

use crate::common::{
    hash_to_scalar, kdf_expand_gt, pairing, pairing_product, random_nonzero_scalar, serialize,
    Scalar, G1, G2, GT,
};
use ark_ec::PrimeGroup;
use ark_ff::Zero;
use ark_serialize::CanonicalDeserialize;
use rand::RngCore;

#[derive(Clone)]
pub struct IdentityPublicKey {
    pub index: usize,
    x: G1,
}

#[derive(Clone)]
pub struct IdentitySecretKey {
    pub public: IdentityPublicKey,
    u: Scalar,
}

impl IdentitySecretKey {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        serialize(&self.u)
    }
}

#[derive(Clone)]
pub struct GroupContext {
    recipient_indices: Vec<usize>,
    receiver: usize,
    encryption_key: G1,
    target_key: GT,
    receiver_key: G2,
    receiver_f: G2,
}

#[derive(Clone)]
pub struct GroupEpoch {
    recipient_indices: Vec<usize>,
    encryption_key: G1,
    target_key: GT,
    sum_u: Scalar,
    sum_pu: Scalar,
    sum_z: Scalar,
}

/// One member's local agreement contribution before coordinator aggregation.
#[derive(Clone)]
pub struct AgreementContribution {
    u: Scalar,
    pu: Scalar,
    z: Scalar,
}

impl GroupContext {
    pub fn contains(&self, index: usize) -> bool {
        self.recipient_indices.contains(&index)
    }
}

#[derive(Clone)]
pub struct Ciphertext {
    c1: G1,
    c2: G1,
    encrypted_body: Vec<u8>,
}

impl Ciphertext {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = serialize(&self.c1);
        bytes.extend_from_slice(&serialize(&self.c2));
        bytes.extend_from_slice(&self.encrypted_body);
        bytes
    }
}

pub struct Zhang23 {
    g1: G1,
    g2: G2,
    group_id: [u8; 16],
}

impl Zhang23 {
    pub fn setup() -> Self {
        Self {
            g1: G1::generator(),
            g2: G2::generator(),
            group_id: *b"Zhang23/session!",
        }
    }

    pub fn keygen(&self, index: usize, rng: &mut impl RngCore) -> IdentitySecretKey {
        let u = random_nonzero_scalar(rng);
        IdentitySecretKey {
            public: IdentityPublicKey {
                index,
                x: self.g1 * u,
            },
            u,
        }
    }

    /// Executes Agreement plus Enc.KeyGen and the selected member's Dec.KeyGen
    /// for a full active group. This is session-establishment work.
    pub fn prepare_group(
        &self,
        participants: &[IdentitySecretKey],
        receiver: usize,
        rng: &mut impl RngCore,
    ) -> Option<GroupContext> {
        let epoch = self.agree_group(participants, rng)?;
        self.derive_receiver_context(&epoch, receiver)
    }

    /// Executes Agreement and Enc.KeyGen once for the complete group.
    pub fn agree_group(
        &self,
        participants: &[IdentitySecretKey],
        rng: &mut impl RngCore,
    ) -> Option<GroupEpoch> {
        if participants.is_empty() {
            return None;
        }
        let u0 = self.g2 * hash_to_scalar(b"Zhang23/H1/0", &[&self.group_id]);
        let u1 = self.g2 * hash_to_scalar(b"Zhang23/H1/1", &[&self.group_id]);
        let mut sum_u = Scalar::zero();
        let mut sum_pu = Scalar::zero();
        let mut sum_z = Scalar::zero();
        for member in participants {
            let contribution = self.create_agreement_contribution(member, rng);
            sum_u += contribution.u;
            sum_pu += contribution.pu;
            sum_z += contribution.z;
        }
        let encryption_key = self.g1 * sum_z;
        let target_key = pairing(self.g1 * sum_u, u0) + pairing(self.g1 * sum_pu, u1);
        Some(GroupEpoch {
            recipient_indices: participants
                .iter()
                .map(|member| member.public.index)
                .collect(),
            encryption_key,
            target_key,
            sum_u,
            sum_pu,
            sum_z,
        })
    }

    /// Generates the contribution computed locally by one agreement member.
    pub fn create_agreement_contribution(
        &self,
        member: &IdentitySecretKey,
        rng: &mut impl RngCore,
    ) -> AgreementContribution {
        let z = random_nonzero_scalar(rng);
        let r = self.g1 * z;
        let index_bytes = (member.public.index as u64).to_le_bytes();
        let p = hash_to_scalar(
            b"Zhang23/H2",
            &[
                &self.group_id,
                &index_bytes,
                &serialize(&member.public.x),
                &serialize(&r),
            ],
        );
        AgreementContribution {
            u: member.u,
            pu: p * member.u,
            z,
        }
    }

    /// Executes one member's Dec.KeyGen from an established group epoch.
    pub fn derive_receiver_context(
        &self,
        epoch: &GroupEpoch,
        receiver: usize,
    ) -> Option<GroupContext> {
        if !epoch.recipient_indices.contains(&receiver) {
            return None;
        }
        let u0 = self.g2 * hash_to_scalar(b"Zhang23/H1/0", &[&self.group_id]);
        let u1 = self.g2 * hash_to_scalar(b"Zhang23/H1/1", &[&self.group_id]);
        let receiver_bytes = (receiver as u64).to_le_bytes();
        let receiver_f = self.g2 * hash_to_scalar(b"Zhang23/f", &[&self.group_id, &receiver_bytes]);
        let receiver_key = u0 * epoch.sum_u + u1 * epoch.sum_pu + receiver_f * epoch.sum_z;
        if pairing(self.g1, receiver_key)
            != epoch.target_key + pairing(epoch.encryption_key, receiver_f)
        {
            return None;
        }
        Some(GroupContext {
            recipient_indices: epoch.recipient_indices.clone(),
            receiver,
            encryption_key: epoch.encryption_key,
            target_key: epoch.target_key,
            receiver_key,
            receiver_f,
        })
    }

    pub fn sign_encrypt(
        &self,
        sender: &IdentitySecretKey,
        group: &GroupContext,
        message: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Ciphertext {
        let r = random_nonzero_scalar(rng);
        let c1 = self.g1 * r;
        let c2 = group.encryption_key * r;
        let h = self.g2 * hash_to_scalar(b"Zhang23/H4", &[&serialize(&c1), message]);
        let signature = h * sender.u;
        let mut body = Vec::with_capacity(176);
        body.extend_from_slice(message);
        body.extend_from_slice(&serialize(&sender.public.x));
        body.extend_from_slice(&serialize(&signature));
        let pad = kdf_expand_gt(b"Zhang23/H3", &(group.target_key * r), body.len());
        for (byte, mask) in body.iter_mut().zip(pad) {
            *byte ^= mask;
        }
        Ciphertext {
            c1,
            c2,
            encrypted_body: body,
        }
    }

    pub fn decrypt_verify(
        &self,
        receiver: usize,
        expected_sender: &IdentityPublicKey,
        group: &GroupContext,
        ciphertext: &Ciphertext,
    ) -> Option<[u8; 32]> {
        if group.receiver != receiver || !group.contains(receiver) {
            return None;
        }
        let session = pairing_product(&[
            (ciphertext.c1, group.receiver_key),
            (-ciphertext.c2, group.receiver_f),
        ]);
        let pad = kdf_expand_gt(b"Zhang23/H3", &session, ciphertext.encrypted_body.len());
        let mut body = ciphertext.encrypted_body.clone();
        for (byte, mask) in body.iter_mut().zip(pad) {
            *byte ^= mask;
        }
        if body.len() != 176 {
            return None;
        }
        let mut message = [0u8; 32];
        message.copy_from_slice(&body[..32]);
        let sender_public = G1::deserialize_compressed(&body[32..80]).ok()?;
        let signature = G2::deserialize_compressed(&body[80..]).ok()?;
        if sender_public != expected_sender.x {
            return None;
        }
        let h = self.g2 * hash_to_scalar(b"Zhang23/H4", &[&serialize(&ciphertext.c1), &message]);
        let verification = pairing_product(&[(self.g1, signature), (-sender_public, h)]);
        (verification == GT::zero()).then_some(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn type3_round_trip_serialization_and_tamper_rejection() {
        let mut rng = StdRng::seed_from_u64(2023);
        let scheme = Zhang23::setup();
        let receivers = (1..=8)
            .map(|index| scheme.keygen(index, &mut rng))
            .collect::<Vec<_>>();
        let sender = scheme.keygen(9, &mut rng);
        let group = scheme.prepare_group(&receivers, 1, &mut rng).unwrap();
        let message = [0x23u8; 32];
        let ciphertext = scheme.sign_encrypt(&sender, &group, &message, &mut rng);
        assert_eq!(
            scheme.decrypt_verify(1, &sender.public, &group, &ciphertext),
            Some(message)
        );
        assert_eq!(ciphertext.serialized_bytes().len(), 272);
        assert_eq!(sender.serialized_bytes().len(), 32);

        let mut tampered = ciphertext.clone();
        tampered.encrypted_body[4] ^= 1;
        assert!(scheme
            .decrypt_verify(1, &sender.public, &group, &tampered)
            .is_none());
    }
}
