//! Lee (2025) CCA-secure distributed broadcast encryption.
//!
//! [`Lee25Ss`] implements the semi-static `DBE_SS` construction from Section
//! 4.1. [`Lee25`] implements `DBE_AD` from Section 4.2, including both DBE_SS
//! encapsulations, the Gentry--Waters index doubling, symmetric-key wrapping,
//! and a concrete strongly unforgeable one-time Schnorr signature.

use crate::common::{
    alpha_powers, hash_bytes, hash_to_scalar, kdf_gt, pairing, pairing_product,
    random_nonzero_scalar, serialize, xor32, Scalar, G1, G2, GT,
};
use ark_ec::PrimeGroup;
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_secp256r1::{Fr as P256Scalar, Projective as P256};
use rand::RngCore;

#[derive(Clone)]
struct SsPublicKey {
    index: usize,
    v: G1,
    v_hat: G2,
    cross: Vec<G1>,
}

#[derive(Clone)]
struct SsSecretKey {
    index: usize,
    k: G1,
}

#[derive(Clone)]
pub struct UserPublicKey {
    pub index: usize,
    even: SsPublicKey,
    odd: SsPublicKey,
}

#[derive(Clone)]
pub struct UserSecretKey {
    pub index: usize,
    branch: u8,
    inner: SsSecretKey,
}

#[derive(Clone)]
pub struct User {
    pub public: UserPublicKey,
    pub secret: UserSecretKey,
}

#[derive(Clone)]
struct SsCiphertext {
    c1_hat: G2,
    c2: G1,
}

#[derive(Clone)]
struct OtsSignature {
    commitment: P256,
    response: P256Scalar,
}

#[derive(Clone)]
pub struct Ciphertext {
    ss0: SsCiphertext,
    ss1: SsCiphertext,
    wrapped0: [u8; 32],
    wrapped1: [u8; 32],
    branches: Vec<u8>,
    verification_key: P256,
    signature: OtsSignature,
}

pub struct Lee25 {
    n: usize,
    l: usize,
    g1: G1,
    g2: G2,
    a: Vec<G1>,
    a_hat: Vec<G2>,
    b: G1,
    b_k: Vec<G1>,
    powers: Vec<Scalar>,
    omega_base: GT,
}

#[derive(Clone)]
pub struct Lee25SsPublicKey {
    pub index: usize,
    inner: SsPublicKey,
}

#[derive(Clone)]
pub struct Lee25SsSecretKey {
    pub index: usize,
    inner: SsSecretKey,
}

impl Lee25SsSecretKey {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.index as u64).to_le_bytes());
        bytes.extend_from_slice(&serialize(&self.inner.k));
        bytes
    }
}

#[derive(Clone)]
pub struct Lee25SsCiphertext {
    header: SsCiphertext,
    wrapped_key: [u8; 32],
}

impl Lee25SsCiphertext {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&serialize(&self.header.c1_hat));
        bytes.extend_from_slice(&serialize(&self.header.c2));
        bytes.extend_from_slice(&self.wrapped_key);
        bytes
    }
}

pub struct Lee25Ss {
    core: Lee25,
}

impl Lee25 {
    pub fn setup(n: usize, rng: &mut impl RngCore) -> Self {
        Self::setup_with_slots(n, 2 * n, rng)
    }

    fn setup_with_slots(n: usize, l: usize, rng: &mut impl RngCore) -> Self {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let alpha = random_nonzero_scalar(rng);
        let beta = random_nonzero_scalar(rng);
        let powers = alpha_powers(alpha, 2 * l + 2);
        let mut a = powers.iter().map(|x| g1 * x).collect::<Vec<_>>();
        let a_hat = powers.iter().map(|x| g2 * x).collect::<Vec<_>>();
        let omega_base = pairing(g1 * powers[l + 2], g2);
        a[l + 2] = G1::zero();
        let b = g1 * beta;
        let mut b_k = vec![G1::zero(); l + 2];
        for k in 2..=l + 1 {
            b_k[k] = g1 * (beta * powers[k]);
        }
        Self {
            n,
            l,
            g1,
            g2,
            a,
            a_hat,
            b,
            b_k,
            powers,
            omega_base,
        }
    }

    pub fn keygen(&self, index: usize, rng: &mut impl RngCore) -> User {
        assert!((1..=self.n).contains(&index));
        let (even_secret, even) = self.ss_keygen(2 * index, rng);
        let (odd_secret, odd) = self.ss_keygen(2 * index - 1, rng);
        let branch = (rng.next_u32() & 1) as u8;
        let inner = if branch == 0 { even_secret } else { odd_secret };
        User {
            public: UserPublicKey { index, even, odd },
            secret: UserSecretKey {
                index,
                branch,
                inner,
            },
        }
    }

    fn ss_keygen(&self, index: usize, rng: &mut impl RngCore) -> (SsSecretKey, SsPublicKey) {
        let gamma = random_nonzero_scalar(rng);
        let secret_index = self.l + 2 - index;
        let mut cross = vec![G1::zero(); self.l + 2];
        for (k, value) in cross.iter_mut().enumerate().take(self.l + 2).skip(2) {
            if k != secret_index {
                *value = self.a[k] * gamma;
            }
        }
        (
            SsSecretKey {
                index,
                k: self.g1 * (self.powers[secret_index] * gamma),
            },
            SsPublicKey {
                index,
                v: self.g1 * gamma,
                v_hat: self.g2 * gamma,
                cross,
            },
        )
    }

    pub fn is_valid(&self, public: &UserPublicKey, rng: &mut impl RngCore) -> bool {
        self.ss_is_valid(&public.even, rng) && self.ss_is_valid(&public.odd, rng)
    }

    fn ss_is_valid(&self, public: &SsPublicKey, rng: &mut impl RngCore) -> bool {
        let secret_index = self.l + 2 - public.index;
        let delta0 = Scalar::from((rng.next_u32() as u64) | 1);
        let mut left = public.v * delta0;
        let mut right = self.g1 * delta0;
        for k in 2..=self.l + 1 {
            if k != secret_index {
                let delta = Scalar::from((rng.next_u32() as u64) | 1);
                left += public.cross[k] * delta;
                right += self.a[k] * delta;
            }
        }
        pairing(left, self.g2) == pairing(right, public.v_hat)
    }

    pub fn encaps(
        &self,
        recipients: &[usize],
        public_keys: &[UserPublicKey],
        rng: &mut impl RngCore,
    ) -> (Ciphertext, [u8; 32]) {
        assert!(!recipients.is_empty());
        let (ots_secret, verification_key) = ots_keygen(rng);
        let auxiliary = serialize(&verification_key);
        let mut branches = Vec::with_capacity(recipients.len());
        let mut set0 = Vec::with_capacity(recipients.len());
        let mut set1 = Vec::with_capacity(recipients.len());
        for &j in recipients {
            let z = (rng.next_u32() & 1) as u8;
            branches.push(z);
            set0.push((2 * j - z as usize, select_public(&public_keys[j - 1], z)));
            set1.push((
                2 * j - (1 - z) as usize,
                select_public(&public_keys[j - 1], 1 - z),
            ));
        }
        let (ss0, key0) = self.ss_encaps(&set0, &auxiliary, rng);
        let (ss1, key1) = self.ss_encaps(&set1, &auxiliary, rng);
        let mut common_key = [0u8; 32];
        rng.fill_bytes(&mut common_key);
        let wrapped0 = xor32(&common_key, &kdf_gt(b"Lee25/SKE", &key0));
        let wrapped1 = xor32(&common_key, &kdf_gt(b"Lee25/SKE", &key1));
        let message = ciphertext_message(&ss0, &ss1, &wrapped0, &wrapped1, &branches);
        let signature = ots_sign(ots_secret, &verification_key, &message, rng);
        (
            Ciphertext {
                ss0,
                ss1,
                wrapped0,
                wrapped1,
                branches,
                verification_key,
                signature,
            },
            common_key,
        )
    }

    pub fn decaps(
        &self,
        recipients: &[usize],
        receiver: &UserSecretKey,
        public_keys: &[UserPublicKey],
        ciphertext: &Ciphertext,
        rng: &mut impl RngCore,
    ) -> Option<[u8; 32]> {
        let receiver_position = recipients.iter().position(|i| *i == receiver.index)?;
        let message = ciphertext_message(
            &ciphertext.ss0,
            &ciphertext.ss1,
            &ciphertext.wrapped0,
            &ciphertext.wrapped1,
            &ciphertext.branches,
        );
        if !ots_verify(
            &ciphertext.verification_key,
            &message,
            &ciphertext.signature,
        ) {
            return None;
        }
        let auxiliary = serialize(&ciphertext.verification_key);
        let use_set0 = ciphertext.branches[receiver_position] == receiver.branch;
        let mut selected = Vec::with_capacity(recipients.len());
        for (position, &j) in recipients.iter().enumerate() {
            let z = ciphertext.branches[position];
            let selected_branch = if use_set0 { z } else { 1 - z };
            selected.push((
                2 * j - selected_branch as usize,
                select_public(&public_keys[j - 1], selected_branch),
            ));
        }
        let (ss_ciphertext, wrapped) = if use_set0 {
            (&ciphertext.ss0, &ciphertext.wrapped0)
        } else {
            (&ciphertext.ss1, &ciphertext.wrapped1)
        };
        let session = self.ss_decaps(&selected, &receiver.inner, ss_ciphertext, &auxiliary, rng)?;
        Some(xor32(wrapped, &kdf_gt(b"Lee25/SKE", &session)))
    }

    fn ss_encaps(
        &self,
        recipients: &[(usize, &SsPublicKey)],
        auxiliary: &[u8],
        rng: &mut impl RngCore,
    ) -> (SsCiphertext, GT) {
        let t = random_nonzero_scalar(rng);
        let c1_hat = self.g2 * t;
        let omega = ss_tag(&c1_hat, auxiliary);
        let q = self.ss_recipient_base(recipients, omega);
        (SsCiphertext { c1_hat, c2: q * t }, self.omega_base * t)
    }

    fn ss_decaps(
        &self,
        recipients: &[(usize, &SsPublicKey)],
        secret: &SsSecretKey,
        ciphertext: &SsCiphertext,
        auxiliary: &[u8],
        rng: &mut impl RngCore,
    ) -> Option<GT> {
        if !recipients.iter().any(|(i, _)| *i == secret.index) {
            return None;
        }
        let omega = ss_tag(&ciphertext.c1_hat, auxiliary);
        let q = self.ss_recipient_base(recipients, omega);
        if !pairing_product(&[(ciphertext.c2, self.g2), (-q, ciphertext.c1_hat)]).is_zero() {
            return None;
        }
        let r = random_nonzero_scalar(rng);
        let d1 = secret.k + q * r;
        let d2_hat = self.a_hat[self.l + 2 - secret.index] + self.g2 * r;
        let d3 =
            self.a[2 * self.l + 3 - secret.index] * omega + self.b_k[self.l + 2 - secret.index];
        let mut d4 = G1::zero();
        let cross_index = self.l + 2 - secret.index;
        for (j, public) in recipients {
            if *j != secret.index {
                d4 += self.a[self.l + 2 - secret.index + *j] + public.cross[cross_index];
            }
        }
        Some(pairing_product(&[
            (ciphertext.c2, d2_hat),
            (-(d1 + d3 + d4), ciphertext.c1_hat),
        ]))
    }

    fn ss_recipient_base(&self, recipients: &[(usize, &SsPublicKey)], omega: Scalar) -> G1 {
        let mut q = self.a[self.l + 1] * omega + self.b;
        for (j, public) in recipients {
            debug_assert_eq!(*j, public.index);
            q += self.a[*j] + public.v;
        }
        q
    }
}

impl Lee25Ss {
    pub fn setup(n: usize, rng: &mut impl RngCore) -> Self {
        Self {
            core: Lee25::setup_with_slots(n, n, rng),
        }
    }

    pub fn keygen(
        &self,
        index: usize,
        rng: &mut impl RngCore,
    ) -> (Lee25SsPublicKey, Lee25SsSecretKey) {
        assert!((1..=self.core.n).contains(&index));
        let (secret, public) = self.core.ss_keygen(index, rng);
        (
            Lee25SsPublicKey {
                index,
                inner: public,
            },
            Lee25SsSecretKey {
                index,
                inner: secret,
            },
        )
    }

    pub fn is_valid(&self, public: &Lee25SsPublicKey, rng: &mut impl RngCore) -> bool {
        public.index == public.inner.index && self.core.ss_is_valid(&public.inner, rng)
    }

    pub fn encaps(
        &self,
        recipients: &[usize],
        public_keys: &[Lee25SsPublicKey],
        auxiliary: &[u8],
        key: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Lee25SsCiphertext {
        let selected = recipients
            .iter()
            .map(|&index| (index, &public_keys[index - 1].inner))
            .collect::<Vec<_>>();
        let (header, session) = self.core.ss_encaps(&selected, auxiliary, rng);
        Lee25SsCiphertext {
            header,
            wrapped_key: xor32(key, &kdf_gt(b"Lee25-SS/KEM", &session)),
        }
    }

    pub fn decaps(
        &self,
        recipients: &[usize],
        receiver: &Lee25SsSecretKey,
        public_keys: &[Lee25SsPublicKey],
        ciphertext: &Lee25SsCiphertext,
        auxiliary: &[u8],
        rng: &mut impl RngCore,
    ) -> Option<[u8; 32]> {
        if !recipients.contains(&receiver.index) {
            return None;
        }
        let selected = recipients
            .iter()
            .map(|&index| (index, &public_keys[index - 1].inner))
            .collect::<Vec<_>>();
        let session = self.core.ss_decaps(
            &selected,
            &receiver.inner,
            &ciphertext.header,
            auxiliary,
            rng,
        )?;
        Some(xor32(
            &ciphertext.wrapped_key,
            &kdf_gt(b"Lee25-SS/KEM", &session),
        ))
    }
}

fn select_public(public: &UserPublicKey, branch: u8) -> &SsPublicKey {
    if branch == 0 {
        &public.even
    } else {
        &public.odd
    }
}

fn ss_tag(c1_hat: &G2, auxiliary: &[u8]) -> Scalar {
    let encoded = serialize(c1_hat);
    hash_to_scalar(b"Lee25/H1", &[&encoded, auxiliary])
}

fn ciphertext_message(
    ss0: &SsCiphertext,
    ss1: &SsCiphertext,
    wrapped0: &[u8; 32],
    wrapped1: &[u8; 32],
    branches: &[u8],
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&serialize(&ss0.c1_hat));
    message.extend_from_slice(&serialize(&ss0.c2));
    message.extend_from_slice(&serialize(&ss1.c1_hat));
    message.extend_from_slice(&serialize(&ss1.c2));
    message.extend_from_slice(wrapped0);
    message.extend_from_slice(wrapped1);
    message.extend_from_slice(branches);
    message
}

fn ots_keygen(rng: &mut impl RngCore) -> (P256Scalar, P256) {
    let mut secret = P256Scalar::rand(rng);
    while secret.is_zero() {
        secret = P256Scalar::rand(rng);
    }
    (secret, P256::generator() * secret)
}

fn ots_sign(
    secret: P256Scalar,
    verification_key: &P256,
    message: &[u8],
    rng: &mut impl RngCore,
) -> OtsSignature {
    let mut nonce = P256Scalar::rand(rng);
    while nonce.is_zero() {
        nonce = P256Scalar::rand(rng);
    }
    let commitment = P256::generator() * nonce;
    let challenge = ots_challenge(verification_key, &commitment, message);
    OtsSignature {
        commitment,
        response: nonce + challenge * secret,
    }
}

fn ots_verify(verification_key: &P256, message: &[u8], signature: &OtsSignature) -> bool {
    let challenge = ots_challenge(verification_key, &signature.commitment, message);
    P256::generator() * signature.response == signature.commitment + *verification_key * challenge
}

fn ots_challenge(verification_key: &P256, commitment: &P256, message: &[u8]) -> P256Scalar {
    let vk = serialize(verification_key);
    let r = serialize(commitment);
    P256Scalar::from_be_bytes_mod_order(&hash_bytes(b"Lee25/OTS", &[&vk, &r, message]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn adaptive_cca_round_trip_and_integrity() {
        let mut rng = StdRng::seed_from_u64(2025);
        let scheme = Lee25::setup(8, &mut rng);
        let users = (1..=8)
            .map(|i| scheme.keygen(i, &mut rng))
            .collect::<Vec<_>>();
        for user in &users {
            assert!(scheme.is_valid(&user.public, &mut rng));
        }
        let public = users.iter().map(|u| u.public.clone()).collect::<Vec<_>>();
        let recipients = [1usize, 2, 5, 8];
        let (ciphertext, key) = scheme.encaps(&recipients, &public, &mut rng);
        assert_eq!(
            scheme.decaps(
                &recipients,
                &users[4].secret,
                &public,
                &ciphertext,
                &mut rng,
            ),
            Some(key)
        );
        let mut tampered = ciphertext;
        tampered.wrapped0[0] ^= 1;
        assert!(scheme
            .decaps(&recipients, &users[4].secret, &public, &tampered, &mut rng,)
            .is_none());
    }

    #[test]
    fn semi_static_cca_round_trip_integrity_and_serialization() {
        let mut rng = StdRng::seed_from_u64(0x1EE2_5001);
        let scheme = Lee25Ss::setup(16, &mut rng);
        let users = (1..=16)
            .map(|index| scheme.keygen(index, &mut rng))
            .collect::<Vec<_>>();
        assert!(users
            .iter()
            .all(|(public, _)| scheme.is_valid(public, &mut rng)));
        let public_keys = users
            .iter()
            .map(|(public, _)| public.clone())
            .collect::<Vec<_>>();
        let recipients = [1usize, 4, 7, 11, 16];
        let key = [0x5A; 32];
        let ciphertext = scheme.encaps(&recipients, &public_keys, b"", &key, &mut rng);
        assert_eq!(
            scheme.decaps(
                &recipients,
                &users[6].1,
                &public_keys,
                &ciphertext,
                b"",
                &mut rng,
            ),
            Some(key)
        );
        assert_eq!(ciphertext.serialized_bytes().len(), 176);

        let mut tampered = ciphertext;
        tampered.header.c2 += G1::generator();
        assert!(scheme
            .decaps(
                &recipients,
                &users[6].1,
                &public_keys,
                &tampered,
                b"",
                &mut rng,
            )
            .is_none());
    }
}


// Receiver-specific timing fixture. Unused cross coordinates remain placeholders;
// this is not a complete public-key directory or a full IsValid measurement.
impl Lee25Ss {
    pub fn quick_receiver_fixture_keygen(
        &self, index: usize, receiver: usize, rng: &mut impl RngCore,
    ) -> (Lee25SsPublicKey, Lee25SsSecretKey) {
        assert!((1..=self.core.n).contains(&index));
        assert!((1..=self.core.n).contains(&receiver));
        let gamma = random_nonzero_scalar(rng);
        let secret_index = self.core.l + 2 - index;
        let cross_index = self.core.l + 2 - receiver;
        let mut cross = vec![G1::zero(); self.core.l + 2];
        if cross_index != secret_index { cross[cross_index] = self.core.a[cross_index] * gamma; }
        let public = SsPublicKey {
            index, v: self.core.g1 * gamma, v_hat: self.core.g2 * gamma, cross,
        };
        let secret = SsSecretKey {
            index, k: self.core.g1 * (self.core.powers[secret_index] * gamma),
        };
        (
            Lee25SsPublicKey { index, inner: public },
            Lee25SsSecretKey { index, inner: secret },
        )
    }

    // Original successful ss_is_valid consumes one delta0 and l-1 deltas.
    // Consume exactly those random draws; no public-key validation is performed.
    pub fn advance_fixture_validation_rng(&self, rng: &mut impl RngCore) {
        for _ in 0..self.core.l { let _ = rng.next_u32(); }
    }

    pub fn assert_quick_fixture_fields_equal(
        &self,
        projected_public: &Lee25SsPublicKey, projected_secret: &Lee25SsSecretKey,
        full_public: &Lee25SsPublicKey, full_secret: &Lee25SsSecretKey,
        receiver: usize,
    ) {
        assert_eq!(projected_public.index, full_public.index);
        assert_eq!(projected_public.inner.index, full_public.inner.index);
        assert_eq!(projected_public.inner.v, full_public.inner.v);
        assert_eq!(projected_public.inner.v_hat, full_public.inner.v_hat);
        assert_eq!(projected_public.inner.cross.len(), self.core.l + 2);
        assert_eq!(projected_public.inner.cross.len(), full_public.inner.cross.len());
        let cross_index = self.core.l + 2 - receiver;
        assert_eq!(projected_public.inner.cross[cross_index], full_public.inner.cross[cross_index]);
        assert_eq!(projected_secret.serialized_bytes(), full_secret.serialized_bytes());
    }
}
