//! Attrapadung--Furukawa--Imai (ASIACRYPT 2006) FS-BE baseline.
//!
//! Equation mapping:
//! - [`Afi06::setup`], [`Afi06::register`], [`Afi06::derive`],
//!   [`Afi06::encrypt_cached`], and [`Afi06::decrypt_cached`] implement
//!   `BasicHICBE2` in Section 4.2.
//! - [`Afi06::initial_state`] and [`Afi06::update_state`] implement the preorder
//!   time-tree conversion `C(HICBE => FS-BE)` described in Section 5. A state
//!   keeps the current h-node key and the future right siblings on its path.
//! - The paper presents symmetric groups and explicitly permits an asymmetric
//!   reformulation. Ciphertext coordinates are placed in G1 and private-key
//!   coordinates in G2 on BLS12-381.
//! - The source construction is a KEM. This implementation applies a
//!   domain-separated KDF to its target-group key and wraps a 32-byte content
//!   key, without changing the three source header coordinates.

use crate::common::{
    alpha_powers, kdf_gt, pairing, pairing_product, random_nonzero_scalar, serialize, xor32,
    Scalar, G1, G2, GT,
};
use ark_ec::PrimeGroup;
use ark_ff::Zero;
use rand::RngCore;

#[derive(Clone)]
pub struct UserKey {
    pub index: usize,
    pub node: Vec<u8>,
    a0: G2,
    a1: G2,
    helpers: Vec<G2>,
}

impl UserKey {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.index as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.node.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.node);
        bytes.extend_from_slice(&serialize(&self.a0));
        bytes.extend_from_slice(&serialize(&self.a1));
        for helper in self.helpers.iter().skip(self.node.len() + 1) {
            bytes.extend_from_slice(&serialize(helper));
        }
        bytes
    }

    pub fn number_of_g2_elements(&self) -> usize {
        2 + self.helpers.len() - self.node.len() - 1
    }
}

#[derive(Clone)]
pub struct ForwardSecureState {
    current: UserKey,
    future_right_siblings: Vec<UserKey>,
}

impl ForwardSecureState {
    pub fn current(&self) -> &UserKey {
        &self.current
    }

    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.future_right_siblings.len() as u64).to_le_bytes());
        let current = self.current.serialized_bytes();
        bytes.extend_from_slice(&(current.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&current);
        for key in &self.future_right_siblings {
            let serialized = key.serialized_bytes();
            bytes.extend_from_slice(&(serialized.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&serialized);
        }
        bytes
    }

    pub fn number_of_g2_elements(&self) -> usize {
        self.current.number_of_g2_elements()
            + self
                .future_right_siblings
                .iter()
                .map(UserKey::number_of_g2_elements)
                .sum::<usize>()
    }
}

#[derive(Clone)]
pub struct TimeCache {
    pub node: Vec<u8>,
    identity1: G1,
    identity2: G2,
}

#[derive(Clone)]
pub struct RecipientCache {
    recipients: Vec<usize>,
    encrypt_base: G1,
    receiver_terms: Vec<Option<G2>>,
}

#[derive(Clone)]
pub struct Ciphertext {
    c0: G1,
    c1: G1,
    c2: G1,
    wrapped_key: [u8; 32],
}

impl Ciphertext {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&serialize(&self.c0));
        bytes.extend_from_slice(&serialize(&self.c1));
        bytes.extend_from_slice(&serialize(&self.c2));
        bytes.extend_from_slice(&self.wrapped_key);
        bytes
    }
}

pub struct Afi06 {
    n: usize,
    depth: usize,
    g1: G1,
    g2: G2,
    g1_powers: Vec<G1>,
    g2_powers: Vec<G2>,
    scalar_powers: Vec<Scalar>,
    gamma: Scalar,
    v1: G1,
    y1: G1,
    y2: G2,
    target_base: GT,
}

impl Afi06 {
    pub fn setup(n: usize, depth: usize, rng: &mut impl RngCore) -> Self {
        assert!(n > depth);
        let g1 = G1::generator();
        let g2 = G2::generator();
        let alpha = random_nonzero_scalar(rng);
        let gamma = random_nonzero_scalar(rng);
        let y = random_nonzero_scalar(rng);
        let scalar_powers = alpha_powers(alpha, 2 * n + 1);
        let mut g1_powers = scalar_powers.iter().map(|x| g1 * x).collect::<Vec<_>>();
        let mut g2_powers = scalar_powers.iter().map(|x| g2 * x).collect::<Vec<_>>();
        g1_powers[n + 1] = G1::zero();
        g2_powers[n + 1] = G2::zero();
        let target_base = pairing(g1_powers[n], g2_powers[1]);
        Self {
            n,
            depth,
            g1,
            g2,
            g1_powers,
            g2_powers,
            scalar_powers,
            gamma,
            v1: g1 * gamma,
            y1: g1 * y,
            y2: g2 * y,
            target_base,
        }
    }

    pub fn register(&self, index: usize, rng: &mut impl RngCore) -> UserKey {
        assert!((1..=self.n).contains(&index));
        let s = random_nonzero_scalar(rng);
        let mut helpers = vec![G2::zero(); self.depth + 1];
        for (level, helper) in helpers.iter_mut().enumerate().take(self.depth + 1).skip(1) {
            *helper = self.g2_powers[self.n + 1 - level] * s;
        }
        UserKey {
            index,
            node: Vec::new(),
            a0: self.g2 * (self.gamma * self.scalar_powers[index]) + self.y2 * s,
            a1: self.g2 * s,
            helpers,
        }
    }

    pub fn derive(&self, current: &UserKey, child_bit: u8, rng: &mut impl RngCore) -> UserKey {
        assert!(child_bit <= 1);
        let z = current.node.len() + 1;
        assert!(z <= self.depth);
        let label = child_bit + 1;
        let delta = random_nonzero_scalar(rng);
        let mut node = current.node.clone();
        node.push(label);
        let identity = self.prepare_time(&node);
        let mut helpers = current.helpers.clone();
        let consumed_helper = helpers[z];
        helpers[z] = G2::zero();
        for (level, helper) in helpers
            .iter_mut()
            .enumerate()
            .take(self.depth + 1)
            .skip(z + 1)
        {
            *helper += self.g2_powers[self.n + 1 - level] * delta;
        }
        UserKey {
            index: current.index,
            node,
            a0: current.a0
                + consumed_helper * Scalar::from(label as u64)
                + identity.identity2 * delta,
            a1: current.a1 + self.g2 * delta,
            helpers,
        }
    }

    pub fn initial_state(&self, index: usize, rng: &mut impl RngCore) -> ForwardSecureState {
        ForwardSecureState {
            current: self.register(index, rng),
            future_right_siblings: Vec::new(),
        }
    }

    pub fn update_state(
        &self,
        state: &ForwardSecureState,
        rng: &mut impl RngCore,
    ) -> Option<ForwardSecureState> {
        let mut future = state.future_right_siblings.clone();
        let current = if state.current.node.len() < self.depth {
            // The right child becomes the new path's future sibling. The left
            // child is the next node in preorder. Both parent-derived keys are
            // produced before the parent state is discarded.
            let right = self.derive(&state.current, 1, rng);
            let left = self.derive(&state.current, 0, rng);
            future.push(right);
            left
        } else {
            future.pop()?
        };
        Some(ForwardSecureState {
            current,
            future_right_siblings: future,
        })
    }

    pub fn prepare_time(&self, node: &[u8]) -> TimeCache {
        let mut identity1 = self.y1;
        let mut identity2 = self.y2;
        for (offset, label) in node.iter().enumerate() {
            assert!(*label == 1 || *label == 2);
            let level = offset + 1;
            let scalar = Scalar::from(*label as u64);
            identity1 += self.g1_powers[self.n + 1 - level] * scalar;
            identity2 += self.g2_powers[self.n + 1 - level] * scalar;
        }
        TimeCache {
            node: node.to_vec(),
            identity1,
            identity2,
        }
    }

    pub fn prepare_recipients(&self, recipients: &[usize], keys: &[UserKey]) -> RecipientCache {
        let mut cache = self.prepare_encrypt_recipients(recipients);
        for &receiver in recipients {
            self.add_receiver_context(&mut cache, receiver, &keys[receiver - 1]);
        }
        cache
    }

    pub fn prepare_encrypt_recipients(&self, recipients: &[usize]) -> RecipientCache {
        let mut encrypt_base = self.v1;
        for &j in recipients {
            encrypt_base += self.g1_powers[self.n + 1 - j];
        }
        RecipientCache {
            recipients: recipients.to_vec(),
            encrypt_base,
            receiver_terms: vec![None; self.n + 1],
        }
    }

    pub fn prepare_receiver_recipients(&self, recipients: &[usize]) -> RecipientCache {
        RecipientCache {
            recipients: recipients.to_vec(),
            encrypt_base: G1::zero(),
            receiver_terms: vec![None; self.n + 1],
        }
    }

    pub fn add_receiver_context(
        &self,
        cache: &mut RecipientCache,
        receiver: usize,
        receiver_key: &UserKey,
    ) {
        assert!(cache.recipients.contains(&receiver));
        let mut term = receiver_key.a0;
        for &j in &cache.recipients {
            if j != receiver {
                term += self.g2_powers[self.n + 1 - j + receiver];
            }
        }
        cache.receiver_terms[receiver] = Some(term);
    }

    pub fn encrypt_cached(
        &self,
        recipients: &RecipientCache,
        time: &TimeCache,
        key: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Ciphertext {
        let t = random_nonzero_scalar(rng);
        let session = self.target_base * t;
        let _ = &recipients.recipients;
        Ciphertext {
            c0: self.g1 * t,
            c1: recipients.encrypt_base * t,
            c2: time.identity1 * t,
            wrapped_key: xor32(key, &kdf_gt(b"AFI06/KEM", &session)),
        }
    }

    pub fn decrypt_cached(
        &self,
        receiver: usize,
        receiver_key: &UserKey,
        recipients: &RecipientCache,
        time: &TimeCache,
        ciphertext: &Ciphertext,
    ) -> Option<[u8; 32]> {
        if receiver_key.node != time.node {
            return None;
        }
        let term = recipients
            .receiver_terms
            .get(receiver)
            .and_then(|entry| *entry)?;
        let session = pairing_product(&[
            (ciphertext.c1, self.g2_powers[receiver]),
            (ciphertext.c2, receiver_key.a1),
            (-ciphertext.c0, term),
        ]);
        Some(xor32(
            &ciphertext.wrapped_key,
            &kdf_gt(b"AFI06/KEM", &session),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn forward_secure_node_round_trip() {
        let mut rng = StdRng::seed_from_u64(2006);
        let scheme = Afi06::setup(16, 4, &mut rng);
        let mut keys = (1..=16)
            .map(|i| scheme.register(i, &mut rng))
            .collect::<Vec<_>>();
        for bit in [0u8, 1, 1] {
            for key in &mut keys {
                *key = scheme.derive(key, bit, &mut rng);
            }
        }
        let time = scheme.prepare_time(&keys[0].node);
        let recipients = scheme.prepare_recipients(&[2, 3, 8, 14], &keys);
        let key = [0xabu8; 32];
        let ciphertext = scheme.encrypt_cached(&recipients, &time, &key, &mut rng);
        assert_eq!(
            scheme.decrypt_cached(8, &keys[7], &recipients, &time, &ciphertext),
            Some(key)
        );
        assert_eq!(
            scheme.decrypt_cached(1, &keys[0], &recipients, &time, &ciphertext),
            None
        );
        assert_eq!(ciphertext.serialized_bytes().len(), 176);
    }

    #[test]
    fn conversion_state_advances_in_preorder_and_drops_the_parent() {
        let mut rng = StdRng::seed_from_u64(0xAF10_6001);
        let scheme = Afi06::setup(16, 4, &mut rng);
        let root = scheme.initial_state(3, &mut rng);
        assert!(root.current().node.is_empty());
        assert_eq!(root.number_of_g2_elements(), 6);

        let left = scheme.update_state(&root, &mut rng).unwrap();
        assert_eq!(left.current().node, vec![1]);
        assert_eq!(left.future_right_siblings.len(), 1);
        assert_eq!(left.future_right_siblings[0].node, vec![2]);
        assert_eq!(left.number_of_g2_elements(), 10);

        let left_left = scheme.update_state(&left, &mut rng).unwrap();
        assert_eq!(left_left.current().node, vec![1, 1]);
        assert!(left_left.current.helpers.iter().take(3).all(Zero::is_zero));
    }
}
