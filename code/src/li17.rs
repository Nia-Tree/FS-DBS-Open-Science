//! Li--Zhang 2017 identity-based AAGKAwSNP, Section 4.1.
//!
//! The source construction uses a symmetric source group. This Type-3 port
//! places the group decryption path in G2 and the two ciphertext coordinates
//! in G1. The identity signature coordinate is placed in G1, so verification
//! remains `e(F, P) = e(C1 + h Q_{id,2}, P_pub)` without an isomorphism.

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
    q0: G2,
    q1: G2,
    q2: G1,
}

#[derive(Clone)]
pub struct IdentitySecretKey {
    pub public: IdentityPublicKey,
    s0: G2,
    s1: G2,
    s2: G1,
}

impl IdentitySecretKey {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = serialize(&self.s0);
        bytes.extend_from_slice(&serialize(&self.s1));
        bytes.extend_from_slice(&serialize(&self.s2));
        bytes
    }
}

#[derive(Clone)]
pub struct GroupContext {
    recipient_indices: Vec<usize>,
    receiver: usize,
    encryption_key: G1,
    zeta: GT,
    receiver_key: G2,
    receiver_w: G2,
}

#[derive(Clone)]
pub struct GroupEpoch {
    recipient_indices: Vec<usize>,
    encryption_key: G1,
    zeta: GT,
    identity_sum: G2,
    r_sum: Scalar,
    z_sum: Scalar,
}

/// One member's agreement contribution before coordinator aggregation.
///
/// The scalars remain internal to this faithful executable model. Exposing the
/// contribution as a value lets the benchmark isolate the member-side work
/// without timing the coordinator's loop over the complete group.
#[derive(Clone)]
pub struct AgreementContribution {
    identity_term: G2,
    r: Scalar,
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

pub struct Li17 {
    p1: G1,
    p2: G2,
    p_pub1: G1,
    p_pub2: G2,
    master_secret: Scalar,
    session_id: [u8; 16],
}

impl Li17 {
    pub fn setup(rng: &mut impl RngCore) -> Self {
        let p1 = G1::generator();
        let p2 = G2::generator();
        let master_secret = random_nonzero_scalar(rng);
        Self {
            p1,
            p2,
            p_pub1: p1 * master_secret,
            p_pub2: p2 * master_secret,
            master_secret,
            session_id: *b"FSDBS-LI17-SID!!",
        }
    }

    pub fn extract(&self, index: usize) -> IdentitySecretKey {
        let index_bytes = (index as u64).to_le_bytes();
        let q0_scalar = hash_to_scalar(b"Li17/H1/0", &[&index_bytes]);
        let q1_scalar = hash_to_scalar(b"Li17/H1/1", &[&index_bytes]);
        let q2_scalar = hash_to_scalar(b"Li17/H1/2", &[&index_bytes]);
        let public = IdentityPublicKey {
            index,
            q0: self.p2 * q0_scalar,
            q1: self.p2 * q1_scalar,
            q2: self.p1 * q2_scalar,
        };
        IdentitySecretKey {
            s0: public.q0 * self.master_secret,
            s1: public.q1 * self.master_secret,
            s2: public.q2 * self.master_secret,
            public,
        }
    }

    /// Executes the Agreement, Enc.KeyGen, and receiver's Dec.KeyGen algebra.
    /// The resulting context is reused by the online group-send path.
    pub fn prepare_group(
        &self,
        participants: &[IdentityPublicKey],
        receiver: usize,
        rng: &mut impl RngCore,
    ) -> Option<GroupContext> {
        let epoch = self.agree_group(participants, rng)?;
        self.derive_receiver_context(&epoch, receiver)
    }

    /// Executes Agreement and Enc.KeyGen once for the complete group.
    pub fn agree_group(
        &self,
        participants: &[IdentityPublicKey],
        rng: &mut impl RngCore,
    ) -> Option<GroupEpoch> {
        if participants.is_empty() {
            return None;
        }
        let v_scalar = hash_to_scalar(b"Li17/H2", &[&self.session_id]);
        let v = self.p2 * v_scalar;

        let mut r_sum = Scalar::zero();
        let mut z_sum = Scalar::zero();
        let mut identity_sum = G2::zero();
        for participant in participants {
            let contribution = self.create_agreement_contribution(participant, rng);
            identity_sum += contribution.identity_term;
            r_sum += contribution.r;
            z_sum += contribution.z;
        }

        let encryption_key = self.p1 * r_sum;
        let zeta = pairing(self.p_pub1, identity_sum) + pairing(self.p1 * z_sum, v);
        Some(GroupEpoch {
            recipient_indices: participants.iter().map(|key| key.index).collect(),
            encryption_key,
            zeta,
            identity_sum,
            r_sum,
            z_sum,
        })
    }

    /// Generates the contribution computed locally by one agreement member.
    pub fn create_agreement_contribution(
        &self,
        participant: &IdentityPublicKey,
        rng: &mut impl RngCore,
    ) -> AgreementContribution {
        let r = random_nonzero_scalar(rng);
        let z = random_nonzero_scalar(rng);
        let r_point = self.p1 * r;
        let z_point = self.p1 * z;
        let index_bytes = (participant.index as u64).to_le_bytes();
        let f = hash_to_scalar(
            b"Li17/H4",
            &[
                &self.session_id,
                &index_bytes,
                &serialize(&r_point),
                &serialize(&z_point),
            ],
        );
        AgreementContribution {
            identity_term: participant.q0 + participant.q1 * f,
            r,
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
        let v_scalar = hash_to_scalar(b"Li17/H2", &[&self.session_id]);
        let v = self.p2 * v_scalar;
        let receiver_bytes = (receiver as u64).to_le_bytes();
        let receiver_w = self.p2 * hash_to_scalar(b"Li17/H3", &[&self.session_id, &receiver_bytes]);
        let receiver_key =
            epoch.identity_sum * self.master_secret + v * epoch.z_sum + receiver_w * epoch.r_sum;
        if pairing(self.p1, receiver_key) != epoch.zeta + pairing(epoch.encryption_key, receiver_w)
        {
            return None;
        }
        Some(GroupContext {
            recipient_indices: epoch.recipient_indices.clone(),
            receiver,
            encryption_key: epoch.encryption_key,
            zeta: epoch.zeta,
            receiver_key,
            receiver_w,
        })
    }

    pub fn sign_encrypt(
        &self,
        sender: &IdentitySecretKey,
        group: &GroupContext,
        message: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Ciphertext {
        let x = random_nonzero_scalar(rng);
        let c1 = self.p1 * x;
        let sender_bytes = (sender.public.index as u64).to_le_bytes();
        let h = hash_to_scalar(b"Li17/H6", &[&serialize(&c1), message, &sender_bytes]);
        let signature = sender.s2 * h + self.p_pub1 * x;
        let c2 = group.encryption_key * x;
        let mut body = Vec::with_capacity(88);
        body.extend_from_slice(&sender_bytes);
        body.extend_from_slice(message);
        body.extend_from_slice(&serialize(&signature));
        let pad = kdf_expand_gt(b"Li17/H5", &(group.zeta * x), body.len());
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
            (-ciphertext.c2, group.receiver_w),
        ]);
        let pad = kdf_expand_gt(b"Li17/H5", &session, ciphertext.encrypted_body.len());
        let mut body = ciphertext.encrypted_body.clone();
        for (byte, mask) in body.iter_mut().zip(pad) {
            *byte ^= mask;
        }
        if body.len() != 88 {
            return None;
        }
        let sender_index = u64::from_le_bytes(body[..8].try_into().ok()?) as usize;
        if sender_index != expected_sender.index {
            return None;
        }
        let mut message = [0u8; 32];
        message.copy_from_slice(&body[8..40]);
        let signature = G1::deserialize_compressed(&body[40..]).ok()?;
        let sender_bytes = (sender_index as u64).to_le_bytes();
        let h = hash_to_scalar(
            b"Li17/H6",
            &[&serialize(&ciphertext.c1), &message, &sender_bytes],
        );
        let verification = pairing_product(&[
            (signature, self.p2),
            (-(ciphertext.c1 + expected_sender.q2 * h), self.p_pub2),
        ]);
        (verification == GT::zero()).then_some(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn type3_round_trip_serialization_and_tamper_rejection() {
        let mut rng = StdRng::seed_from_u64(2017);
        let scheme = Li17::setup(&mut rng);
        let receivers = (1..=8).map(|i| scheme.extract(i)).collect::<Vec<_>>();
        let public = receivers
            .iter()
            .map(|user| user.public.clone())
            .collect::<Vec<_>>();
        let sender = scheme.extract(9);
        let group = scheme.prepare_group(&public, 1, &mut rng).unwrap();
        let message = [0x17u8; 32];
        let ciphertext = scheme.sign_encrypt(&sender, &group, &message, &mut rng);
        assert_eq!(
            scheme.decrypt_verify(1, &sender.public, &group, &ciphertext),
            Some(message)
        );
        assert_eq!(ciphertext.serialized_bytes().len(), 184);
        assert_eq!(sender.serialized_bytes().len(), 240);

        let mut tampered = ciphertext.clone();
        tampered.encrypted_body[12] ^= 1;
        assert!(scheme
            .decrypt_verify(1, &sender.public, &group, &tampered)
            .is_none());
    }
}
