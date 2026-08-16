//! Implementation of the FS-DBS construction in `sigconf.tex`.
//!
//! Paper mapping:
//! - Construction section, `Setup` -> [`FsDbs::setup`]
//! - Construction section, `Join` -> [`FsDbs::join`]
//! - Construction section, `KeyUpdate` -> [`FsDbs::update_key`]
//! - Construction section, `Signcrypt` -> [`FsDbs::signcrypt_cached`]
//! - Construction section, `Unsigncrypt` -> [`FsDbs::unsigncrypt_cached`]
//!
//! The paper labels algorithms rather than individual displayed equations in
//! the supplied manuscript. No equation number is invented here.
//!
//! Binary time labels are encoded as non-zero field elements 1 and 2. This is
//! the encoding required by the selective proof's first-differing-component
//! argument; using literal 0/1 labels makes one simulation denominator zero.

use crate::common::{
    alpha_powers, encode_indices, hash_to_scalar_excluding, kdf_gt, pairing, pairing_product,
    random_nonzero_scalar, random_scalar, serialize, xor32, FixedBaseTable, Scalar, G1, G2, GT,
};
use ark_ec::PrimeGroup;
use ark_ff::Zero;
use rand::RngCore;

#[derive(Clone)]
pub struct UserPublicKey {
    pub index: usize,
    pub base: G1,
    cross: Vec<G2>,
}

impl UserPublicKey {
    fn cross(&self, exponent_index: usize) -> G2 {
        self.cross[exponent_index]
    }
}

#[derive(Clone)]
pub struct EvolvingKey {
    pub index: usize,
    pub node: Vec<u8>,
    a0: G2,
    a1: G2,
    helpers: Vec<G2>,
    helper_table: FixedBaseTable<G2>,
}

impl EvolvingKey {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let active_helpers = self.helpers.iter().skip(self.node.len() + 1);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.index as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.node.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.node);
        bytes.extend_from_slice(&serialize(&self.a0));
        bytes.extend_from_slice(&serialize(&self.a1));
        for helper in active_helpers {
            bytes.extend_from_slice(&serialize(helper));
        }
        bytes
    }

    pub fn element_counts(&self) -> (usize, usize, usize) {
        let active_helpers = self.helpers.len() - (self.node.len() + 1);
        (0, 2 + active_helpers, 0)
    }

    pub fn active_helper_count(&self) -> usize {
        self.helpers.len() - (self.node.len() + 1)
    }
}

#[derive(Clone)]
pub struct User {
    pub public: UserPublicKey,
    pub key: EvolvingKey,
}

#[derive(Clone)]
pub struct TimeCache {
    pub node: Vec<u8>,
    z1: G1,
    z1_table: FixedBaseTable<G1>,
    z2_table: FixedBaseTable<G2>,
    auth1_table: FixedBaseTable<G1>,
    auth2_table: FixedBaseTable<G2>,
}

#[derive(Clone)]
pub struct RecipientCache {
    pub recipients: Vec<usize>,
    pub set_encoding: Vec<u8>,
    x_table: FixedBaseTable<G1>,
    receiver_y: Vec<Option<G2>>,
}

#[derive(Clone)]
pub struct VerificationCache {
    sender: usize,
    static_pairing: GT,
}

#[derive(Clone)]
pub struct Ciphertext {
    pub sender: usize,
    pub node: Vec<u8>,
    pub c0: G1,
    pub c1: G1,
    pub c2: G1,
    pub c3: G2,
    pub c4: G2,
    pub wrapped_key: [u8; 32],
}

impl Ciphertext {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.sender as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.node.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.node);
        bytes.extend_from_slice(&serialize(&self.c0));
        bytes.extend_from_slice(&serialize(&self.c1));
        bytes.extend_from_slice(&serialize(&self.c2));
        bytes.extend_from_slice(&serialize(&self.c3));
        bytes.extend_from_slice(&serialize(&self.c4));
        bytes.extend_from_slice(&self.wrapped_key);
        bytes
    }
}

pub struct FsDbs {
    n: usize,
    depth: usize,
    g1: G1,
    g2: G2,
    a1: Vec<G1>,
    a2: Vec<G2>,
    setup_powers: Vec<Scalar>,
    y1: G1,
    y2: G2,
    g1_table: FixedBaseTable<G1>,
    g2_table: FixedBaseTable<G2>,
    target_table: FixedBaseTable<GT>,
}

impl FsDbs {
    pub fn setup(n: usize, depth: usize, rng: &mut impl RngCore) -> Self {
        assert!(n > depth, "the construction requires n > time-tree depth");
        let g1 = G1::generator();
        let g2 = G2::generator();
        let alpha = random_nonzero_scalar(rng);
        let y = random_nonzero_scalar(rng);
        let powers = alpha_powers(alpha, 2 * n + 2);
        let mut a1 = powers.iter().map(|x| g1 * x).collect::<Vec<_>>();
        let mut a2 = powers.iter().map(|x| g2 * x).collect::<Vec<_>>();
        // alpha^(n+1) is deliberately absent from public parameters.
        a1[n + 1] = G1::zero();
        a2[n + 1] = G2::zero();
        let y1 = g1 * y;
        let y2 = g2 * y;
        let target_base = pairing(g1 * powers[1], g2 * powers[n]);
        let g1_table = FixedBaseTable::new(g1);
        let g2_table = FixedBaseTable::new(g2);
        let target_table = FixedBaseTable::new(target_base);
        Self {
            n,
            depth,
            g1,
            g2,
            a1,
            a2,
            setup_powers: powers,
            y1,
            y2,
            g1_table,
            g2_table,
            target_table,
        }
    }

    pub fn join(&self, index: usize, rng: &mut impl RngCore) -> User {
        assert!((1..=self.n).contains(&index));
        let t = random_nonzero_scalar(rng);
        let rho = random_nonzero_scalar(rng);
        let secret_index = self.n + 1 - index;

        let mut cross = vec![G2::zero(); self.n + 1];
        for (q, slot) in cross.iter_mut().enumerate().take(self.n + 1).skip(1) {
            if q != secret_index {
                *slot = self.a2[q] * t;
            }
        }
        let public = UserPublicKey {
            index,
            base: self.g1 * t,
            cross,
        };

        let mut helpers = vec![G2::zero(); self.depth + 2];
        for (level, helper) in helpers.iter_mut().enumerate().take(self.depth + 2).skip(1) {
            *helper = self.a2[self.n + 1 - level] * rho;
        }
        let helper_table = FixedBaseTable::new(helpers[1]);
        let key = EvolvingKey {
            index,
            node: Vec::new(),
            a0: self.g2 * (t * self.setup_powers[secret_index]) + self.y2 * rho,
            a1: self.g2 * rho,
            helpers,
            helper_table,
        };
        User { public, key }
    }

    /// Generates the public-key coordinates accessed by a benchmark that
    /// decrypts for one fixed receiver. Setup is outside every timing window;
    /// omitting unused coordinates avoids quadratic fixture construction.
    pub fn join_public_projection_for_benchmark(
        &self,
        index: usize,
        receiver: usize,
        rng: &mut impl RngCore,
    ) -> UserPublicKey {
        assert!((1..=self.n).contains(&index));
        assert!((1..=self.n).contains(&receiver));
        let t = random_nonzero_scalar(rng);
        let requested_exponent = self.n + 1 - receiver;
        let excluded_exponent = self.n + 1 - index;
        let mut cross = vec![G2::zero(); self.n + 1];
        if requested_exponent != excluded_exponent {
            cross[requested_exponent] = self.a2[requested_exponent] * t;
        }
        UserPublicKey {
            index,
            base: self.g1 * t,
            cross,
        }
    }

    pub fn update_key(
        &self,
        current: &EvolvingKey,
        child_bit: u8,
        rng: &mut impl RngCore,
    ) -> EvolvingKey {
        assert!(child_bit <= 1);
        let z = current.node.len();
        assert!(z < self.depth);
        let label = child_bit + 1;
        let delta = random_scalar(rng);
        let mut child_node = current.node.clone();
        child_node.push(label);
        let child_z2 = self.time_base_g2(&child_node);

        let mut helpers = current.helpers.clone();
        for (level, helper) in helpers
            .iter_mut()
            .enumerate()
            .take(self.depth + 2)
            .skip(z + 2)
        {
            *helper += self.a2[self.n + 1 - level] * delta;
        }
        // The consumed path state is not part of the child key. Clearing it
        // models the secure deletion required by forward security.
        for helper in helpers.iter_mut().take(z + 2).skip(1) {
            *helper = G2::zero();
        }
        let helper_table = FixedBaseTable::new(helpers[z + 2]);
        EvolvingKey {
            index: current.index,
            node: child_node,
            a0: current.a0 + current.helpers[z + 1] * Scalar::from(label as u64) + child_z2 * delta,
            a1: current.a1 + self.g2 * delta,
            helpers,
            helper_table,
        }
    }

    pub fn prepare_time(&self, node: &[u8]) -> TimeCache {
        assert!(node.len() <= self.depth);
        let mut z1 = self.y1;
        let z2 = self.time_base_g2(node);
        for (offset, label) in node.iter().enumerate() {
            assert!(*label == 1 || *label == 2);
            let level = offset + 1;
            let scalar = Scalar::from(*label as u64);
            z1 += self.a1[self.n + 1 - level] * scalar;
        }
        let z = node.len();
        TimeCache {
            node: node.to_vec(),
            z1,
            z1_table: FixedBaseTable::new(z1),
            z2_table: FixedBaseTable::new(z2),
            auth1_table: FixedBaseTable::new(self.a1[self.n - z]),
            auth2_table: FixedBaseTable::new(self.a2[self.n - z]),
        }
    }

    fn time_base_g2(&self, node: &[u8]) -> G2 {
        assert!(node.len() <= self.depth);
        let mut z2 = self.y2;
        for (offset, label) in node.iter().enumerate() {
            assert!(*label == 1 || *label == 2);
            let level = offset + 1;
            z2 += self.a2[self.n + 1 - level] * Scalar::from(*label as u64);
        }
        z2
    }

    pub fn ciphertext_storage(
        &self,
        ciphertext: &Ciphertext,
        recipients: &[usize],
    ) -> (usize, usize, usize) {
        let cryptographic_ciphertext_bytes = ciphertext.serialized_bytes().len();
        let recipient_metadata_bytes = encode_indices(recipients).len();
        (
            cryptographic_ciphertext_bytes,
            recipient_metadata_bytes,
            cryptographic_ciphertext_bytes + recipient_metadata_bytes,
        )
    }

    pub fn prepare_recipients(
        &self,
        recipients: &[usize],
        public_keys: &[UserPublicKey],
        receiver_keys: &[EvolvingKey],
    ) -> RecipientCache {
        let mut cache = self.prepare_encrypt_recipients(recipients, public_keys);
        for &receiver in recipients {
            self.add_receiver_context(
                &mut cache,
                receiver,
                public_keys,
                &receiver_keys[receiver - 1],
            );
        }
        cache
    }

    pub fn prepare_encrypt_recipients(
        &self,
        recipients: &[usize],
        public_keys: &[UserPublicKey],
    ) -> RecipientCache {
        assert!(!recipients.is_empty());
        let mut x = G1::zero();
        for &j in recipients {
            x += public_keys[j - 1].base + self.a1[j];
        }
        RecipientCache {
            recipients: recipients.to_vec(),
            set_encoding: encode_indices(recipients),
            x_table: FixedBaseTable::new(x),
            receiver_y: vec![None; self.n + 1],
        }
    }

    pub fn prepare_receiver_recipients(&self, recipients: &[usize]) -> RecipientCache {
        RecipientCache {
            recipients: recipients.to_vec(),
            set_encoding: encode_indices(recipients),
            x_table: FixedBaseTable::new(G1::zero()),
            receiver_y: vec![None; self.n + 1],
        }
    }

    pub fn add_receiver_context(
        &self,
        cache: &mut RecipientCache,
        receiver: usize,
        public_keys: &[UserPublicKey],
        receiver_key: &EvolvingKey,
    ) {
        assert!(cache.recipients.contains(&receiver));
        let mut y = receiver_key.a0;
        let exponent = self.n + 1 - receiver;
        for &j in &cache.recipients {
            if j != receiver {
                y += public_keys[j - 1].cross(exponent) + self.a2[self.n + 1 - receiver + j];
            }
        }
        cache.receiver_y[receiver] = Some(y);
    }

    pub fn prepare_verification(&self, sender_public: &UserPublicKey) -> VerificationCache {
        VerificationCache {
            sender: sender_public.index,
            static_pairing: pairing(
                -sender_public.base,
                self.a2[self.n + 1 - sender_public.index],
            ),
        }
    }

    pub fn signcrypt_cached(
        &self,
        sender: &EvolvingKey,
        sender_public: &UserPublicKey,
        recipients: &RecipientCache,
        time: &TimeCache,
        key: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Ciphertext {
        assert_eq!(sender.node, time.node);
        let s = random_nonzero_scalar(rng);
        let (delta, c3) = loop {
            let delta = random_scalar(rng);
            let c3 = sender.a1 + self.g2_table.mul(delta);
            if !c3.is_zero() {
                break (delta, c3);
            }
        };
        let c0 = self.g1_table.mul(s);
        let c1 = recipients.x_table.mul(s);
        let c2 = time.z1_table.mul(s);
        let session = self.target_table.mul(s);
        let wrapped_key = xor32(key, &kdf_gt(b"FS-DBS/KEM", &session));
        let h = self.challenge(
            sender.index,
            &recipients.set_encoding,
            &time.node,
            &c0,
            &c1,
            &c2,
            &c3,
            &wrapped_key,
            &session,
        );
        let c4 = sender.a0
            + sender.helper_table.mul(h)
            + time.z2_table.mul(delta)
            + time.auth2_table.mul(delta * h);
        debug_assert_eq!(sender_public.index, sender.index);
        Ciphertext {
            sender: sender.index,
            node: time.node.clone(),
            c0,
            c1,
            c2,
            c3,
            c4,
            wrapped_key,
        }
    }

    pub fn unsigncrypt_cached(
        &self,
        receiver: usize,
        receiver_key: &EvolvingKey,
        sender_public: &UserPublicKey,
        recipients: &RecipientCache,
        time: &TimeCache,
        ciphertext: &Ciphertext,
    ) -> Option<[u8; 32]> {
        let verification = self.prepare_verification(sender_public);
        self.unsigncrypt_online(
            receiver,
            receiver_key,
            sender_public,
            recipients,
            time,
            &verification,
            ciphertext,
        )
    }

    pub fn unsigncrypt_online(
        &self,
        receiver: usize,
        receiver_key: &EvolvingKey,
        sender_public: &UserPublicKey,
        recipients: &RecipientCache,
        time: &TimeCache,
        verification: &VerificationCache,
        ciphertext: &Ciphertext,
    ) -> Option<[u8; 32]> {
        if receiver_key.node != time.node
            || ciphertext.node != time.node
            || ciphertext.sender != sender_public.index
            || verification.sender != sender_public.index
            || ciphertext.c3.is_zero()
        {
            return None;
        }
        let y = recipients
            .receiver_y
            .get(receiver)
            .and_then(|entry| *entry)?;
        let exponent = self.n + 1 - receiver;
        let session = pairing_product(&[
            (ciphertext.c1, self.a2[exponent]),
            (ciphertext.c2, receiver_key.a1),
            (-ciphertext.c0, y),
        ]);
        let h = self.challenge(
            ciphertext.sender,
            &recipients.set_encoding,
            &time.node,
            &ciphertext.c0,
            &ciphertext.c1,
            &ciphertext.c2,
            &ciphertext.c3,
            &ciphertext.wrapped_key,
            &session,
        );
        let dynamic_check = pairing_product(&[
            (self.g1, ciphertext.c4),
            (-(time.z1 + time.auth1_table.mul(h)), ciphertext.c3),
        ]);
        let check = dynamic_check + verification.static_pairing;
        if !check.is_zero() {
            return None;
        }
        Some(xor32(
            &ciphertext.wrapped_key,
            &kdf_gt(b"FS-DBS/KEM", &session),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn challenge(
        &self,
        sender: usize,
        set_encoding: &[u8],
        node: &[u8],
        c0: &G1,
        c1: &G1,
        c2: &G1,
        c3: &G2,
        wrapped_key: &[u8; 32],
        session: &GT,
    ) -> Scalar {
        let sender_bytes = (sender as u64).to_le_bytes();
        let c0_bytes = serialize(c0);
        let c1_bytes = serialize(c1);
        let c2_bytes = serialize(c2);
        let c3_bytes = serialize(c3);
        let session_bytes = serialize(session);
        hash_to_scalar_excluding(
            b"FS-DBS/H1",
            &[
                &sender_bytes,
                set_encoding,
                node,
                &c0_bytes,
                &c1_bytes,
                &c2_bytes,
                &c3_bytes,
                wrapped_key,
                &session_bytes,
            ],
            &[
                Scalar::from(0u64),
                Scalar::from(1u64),
                Scalar::from(2u64),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn signcrypt_round_trip_and_reject_tampering() {
        let mut rng = StdRng::seed_from_u64(7);
        let scheme = FsDbs::setup(16, 4, &mut rng);
        let mut users = (1..=16)
            .map(|i| scheme.join(i, &mut rng))
            .collect::<Vec<_>>();
        let path = [1u8, 0, 1];
        for bit in path {
            for user in &mut users {
                user.key = scheme.update_key(&user.key, bit, &mut rng);
            }
        }
        let pks = users.iter().map(|u| u.public.clone()).collect::<Vec<_>>();
        let keys = users.iter().map(|u| u.key.clone()).collect::<Vec<_>>();
        let recipients = [1usize, 3, 5, 8, 13];
        let recipient_cache = scheme.prepare_recipients(&recipients, &pks, &keys);
        let time_cache = scheme.prepare_time(&keys[0].node);
        let key = [0x42u8; 32];
        let ciphertext = scheme.signcrypt_cached(
            &keys[1],
            &pks[1],
            &recipient_cache,
            &time_cache,
            &key,
            &mut rng,
        );
        assert!(!ciphertext.c3.is_zero());
        let recovered = scheme
            .unsigncrypt_cached(
                5,
                &keys[4],
                &pks[1],
                &recipient_cache,
                &time_cache,
                &ciphertext,
            )
            .expect("authorized receiver must decrypt");
        assert_eq!(recovered, key);

        let mut identity_c3 = ciphertext.clone();
        identity_c3.c3 = G2::zero();
        assert!(scheme
            .unsigncrypt_cached(
                5,
                &keys[4],
                &pks[1],
                &recipient_cache,
                &time_cache,
                &identity_c3,
            )
            .is_none());

        let mut tampered = ciphertext;
        tampered.wrapped_key[0] ^= 1;
        assert!(scheme
            .unsigncrypt_cached(
                5,
                &keys[4],
                &pks[1],
                &recipient_cache,
                &time_cache,
                &tampered,
            )
            .is_none());
    }

    #[test]
    fn key_update_erases_consumed_helpers_and_preserves_correctness() {
        let mut rng = StdRng::seed_from_u64(19);
        let scheme = FsDbs::setup(16, 4, &mut rng);
        let root = scheme.join(1, &mut rng).key;
        assert_eq!(root.active_helper_count(), 5);
        let child = scheme.update_key(&root, 1, &mut rng);
        assert_eq!(child.active_helper_count(), 4);
        assert!(child.helpers[1].is_zero());
        assert!(child.serialized_bytes().len() < root.serialized_bytes().len());
    }

    #[test]
    fn serialization_uses_real_compressed_group_encodings() {
        let mut rng = StdRng::seed_from_u64(23);
        let scheme = FsDbs::setup(16, 4, &mut rng);
        let users = (1..=5)
            .map(|i| scheme.join(i, &mut rng))
            .collect::<Vec<_>>();
        let public = users
            .iter()
            .map(|user| user.public.clone())
            .collect::<Vec<_>>();
        let keys = users
            .iter()
            .map(|user| user.key.clone())
            .collect::<Vec<_>>();
        let recipients = [1usize, 2, 3, 4];
        let cache = scheme.prepare_recipients(&recipients, &public, &keys);
        let time = scheme.prepare_time(&[]);
        let ciphertext =
            scheme.signcrypt_cached(&keys[4], &public[4], &cache, &time, &[7u8; 32], &mut rng);
        let (cryptographic, metadata, total) = scheme.ciphertext_storage(&ciphertext, &recipients);
        assert_eq!(metadata, recipients.len() * 8);
        assert_eq!(total, cryptographic + metadata);
        assert_eq!(cryptographic, ciphertext.serialized_bytes().len());
    }
}
