//! Gao et al. (Information Sciences 2025) RCB-BSC.
//!
//! This module implements the concrete construction in Section 4 of the
//! article: SV, Cert, Signcrypt, Revoke, and Unsigncrypt. The source scheme is
//! pairing-free, so the implementation uses the P-256 prime-order group.

use crate::common::{hash_bytes, serialize, xor32};
use ark_ec::{
    short_weierstrass::SWCurveConfig, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM,
};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand, Zero};
use ark_secp256r1::{Affine, Config, Fq, Fr, Projective};
use rand::RngCore;

#[derive(Clone)]
pub struct PublicKey {
    identity: Vec<u8>,
    t: Projective,
    gamma: Projective,
}

#[derive(Clone)]
pub struct User {
    pub public: PublicKey,
    certificate: Fr,
    secret_value: Fr,
}

impl User {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = serialize(&self.certificate);
        bytes.extend_from_slice(&serialize(&self.secret_value));
        bytes
    }
}

#[derive(Clone)]
struct Participant {
    identity: Vec<u8>,
    x: Fr,
    encryption_base: Projective,
}

#[derive(Clone)]
pub struct SigncryptCache {
    participants: Vec<Participant>,
    // Entry j contains the scalars used to form coefficient lambda_j.
    lagrange_columns: Vec<Vec<Fr>>,
}

#[derive(Clone)]
pub struct ReceiverCache {
    powers: Vec<Fr>,
}

#[derive(Clone)]
pub struct RevocationCache {
    // Each output coefficient is one MSM over the original coefficients.
    transform_rows: Vec<Vec<Fr>>,
}

#[derive(Clone)]
pub struct Ciphertext {
    c_delta: Projective,
    c_message: [u8; 32],
    lambdas: Vec<Projective>,
    phi: Fr,
}

impl Ciphertext {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = serialize(&self.c_delta);
        bytes.extend_from_slice(&self.c_message);
        for lambda in &self.lambdas {
            bytes.extend_from_slice(&serialize(lambda));
        }
        bytes.extend_from_slice(&serialize(&self.phi));
        bytes
    }
}

pub struct Gao25 {
    max_receivers: usize,
    master_secret: Fr,
    p_public: Projective,
}

impl Gao25 {
    pub fn setup(max_receivers: usize, rng: &mut impl RngCore) -> Self {
        assert!(max_receivers > 0);
        let master_secret = random_nonzero(rng);
        let p_public = Projective::generator() * master_secret;
        Self {
            max_receivers,
            master_secret,
            p_public,
        }
    }

    /// Combines the article's SV and Cert interfaces for benchmark setup.
    pub fn register(&self, identity: &[u8], rng: &mut impl RngCore) -> User {
        let secret_value = random_nonzero(rng);
        let gamma = Projective::generator() * secret_value;
        let t_secret = random_nonzero(rng);
        let t = Projective::generator() * t_secret;
        let public = PublicKey {
            identity: identity.to_vec(),
            t,
            gamma,
        };
        let h = self.certificate_hash(&public);
        let certificate = t_secret + h * self.master_secret;
        User {
            public,
            certificate,
            secret_value,
        }
    }

    pub fn prepare_signcrypt(
        &self,
        sender: &PublicKey,
        recipients: &[PublicKey],
    ) -> SigncryptCache {
        assert!(!recipients.is_empty() && recipients.len() <= self.max_receivers);
        assert!(recipients
            .iter()
            .all(|recipient| recipient.identity != sender.identity));

        let participants = std::iter::once(sender)
            .chain(recipients.iter())
            .map(|public| {
                let h = self.certificate_hash(public);
                Participant {
                    identity: public.identity.clone(),
                    x: hash_nonzero_scalar(b"Gao25/H2", &[&public.identity]),
                    encryption_base: public.t + public.gamma + self.p_public * h,
                }
            })
            .collect::<Vec<_>>();
        let xs = participants.iter().map(|entry| entry.x).collect::<Vec<_>>();
        let lagrange_columns = lagrange_columns(&xs);
        SigncryptCache {
            participants,
            lagrange_columns,
        }
    }

    pub fn signcrypt(
        &self,
        sender: &User,
        recipients: &[PublicKey],
        message: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Ciphertext {
        let cache = self.prepare_signcrypt(&sender.public, recipients);
        self.signcrypt_cached(sender, &cache, message, rng)
    }

    pub fn signcrypt_cached(
        &self,
        sender: &User,
        cache: &SigncryptCache,
        message: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Ciphertext {
        assert_eq!(cache.participants[0].identity, sender.public.identity);
        let session_point = Projective::generator() * random_nonzero(rng);
        let delta = random_nonzero(rng);
        let c_delta = Projective::generator() * delta;

        let interpolation_values = cache
            .participants
            .iter()
            .map(|participant| {
                let e_i = participant.encryption_base * delta;
                hash_to_group(b"Gao25/H3", &[&participant.identity, &serialize(&e_i)])
                    + session_point
            })
            .collect::<Vec<_>>();
        let lambdas = interpolate_group(&cache.lagrange_columns, &interpolation_values);

        let pad = hash_bytes(b"Gao25/H4", &[&serialize(&session_point)]);
        let c_message = xor32(message, &pad);
        let h_message = self.message_hash(&c_delta, &sender.public, &session_point, message);
        let phi = h_message * (sender.secret_value + sender.certificate) + delta;
        Ciphertext {
            c_delta,
            c_message,
            lambdas,
            phi,
        }
    }

    pub fn without_revocation(&self, ciphertext: &Ciphertext) -> Ciphertext {
        ciphertext.clone()
    }

    pub fn prepare_receiver(
        &self,
        receiver: &PublicKey,
        coefficient_count: usize,
    ) -> ReceiverCache {
        assert!(coefficient_count > 0);
        let x = hash_nonzero_scalar(b"Gao25/H2", &[&receiver.identity]);
        ReceiverCache {
            powers: scalar_powers(x, coefficient_count),
        }
    }

    pub fn prepare_revocation(
        &self,
        original: &SigncryptCache,
        authorized: &[PublicKey],
    ) -> RevocationCache {
        assert!(!authorized.is_empty());
        let original_receivers = &original.participants[1..];
        assert!(authorized.iter().all(|candidate| original_receivers
            .iter()
            .any(|entry| entry.identity == candidate.identity)));

        let xs = authorized
            .iter()
            .map(|public| hash_nonzero_scalar(b"Gao25/H2", &[&public.identity]))
            .collect::<Vec<_>>();
        let reduced_basis = lagrange_columns(&xs);
        let original_count = original.lagrange_columns.len();
        let evaluation_rows = xs
            .iter()
            .map(|x| scalar_powers(*x, original_count))
            .collect::<Vec<_>>();

        // Combine evaluation and re-interpolation into a single linear map.
        let mut transform_rows = vec![vec![Fr::zero(); original_count]; xs.len()];
        for output in 0..xs.len() {
            for point in 0..xs.len() {
                let weight = reduced_basis[output][point];
                for input in 0..original_count {
                    transform_rows[output][input] += weight * evaluation_rows[point][input];
                }
            }
        }
        RevocationCache { transform_rows }
    }

    pub fn revoke(
        &self,
        ciphertext: &Ciphertext,
        original: &SigncryptCache,
        authorized: &[PublicKey],
    ) -> Ciphertext {
        if authorized.len() + 1 == original.participants.len()
            && authorized.iter().all(|candidate| {
                original.participants[1..]
                    .iter()
                    .any(|entry| entry.identity == candidate.identity)
            })
        {
            return ciphertext.clone();
        }
        let cache = self.prepare_revocation(original, authorized);
        self.revoke_cached(ciphertext, &cache)
    }

    pub fn revoke_cached(&self, ciphertext: &Ciphertext, cache: &RevocationCache) -> Ciphertext {
        assert!(cache
            .transform_rows
            .iter()
            .all(|row| row.len() == ciphertext.lambdas.len()));
        let bases = ciphertext
            .lambdas
            .iter()
            .map(|point| point.into_affine())
            .collect::<Vec<_>>();
        let lambdas = cache
            .transform_rows
            .iter()
            .map(|row| Projective::msm_unchecked(&bases, row))
            .collect();
        Ciphertext {
            c_delta: ciphertext.c_delta,
            c_message: ciphertext.c_message,
            lambdas,
            phi: ciphertext.phi,
        }
    }

    pub fn unsigncrypt(
        &self,
        receiver: &User,
        sender: &PublicKey,
        ciphertext: &Ciphertext,
    ) -> Option<[u8; 32]> {
        let cache = self.prepare_receiver(&receiver.public, ciphertext.lambdas.len());
        self.unsigncrypt_cached(receiver, sender, &cache, ciphertext)
    }

    pub fn unsigncrypt_cached(
        &self,
        receiver: &User,
        sender: &PublicKey,
        cache: &ReceiverCache,
        ciphertext: &Ciphertext,
    ) -> Option<[u8; 32]> {
        if cache.powers.len() != ciphertext.lambdas.len() {
            return None;
        }
        let lambda_bases = ciphertext
            .lambdas
            .iter()
            .map(|point| point.into_affine())
            .collect::<Vec<_>>();
        let xi_hat = Projective::msm_unchecked(&lambda_bases, &cache.powers);
        let e_hat = ciphertext.c_delta * (receiver.certificate + receiver.secret_value);
        let session_point = xi_hat
            - hash_to_group(
                b"Gao25/H3",
                &[&receiver.public.identity, &serialize(&e_hat)],
            );
        let pad = hash_bytes(b"Gao25/H4", &[&serialize(&session_point)]);
        let message = xor32(&ciphertext.c_message, &pad);

        let h_message = self.message_hash(&ciphertext.c_delta, sender, &session_point, &message);
        let h_sender = self.certificate_hash(sender);
        let left = Projective::generator() * ciphertext.phi;
        let right =
            (sender.gamma + sender.t + self.p_public * h_sender) * h_message + ciphertext.c_delta;
        (left == right).then_some(message)
    }

    fn certificate_hash(&self, public: &PublicKey) -> Fr {
        hash_nonzero_scalar(
            b"Gao25/H1",
            &[
                &public.identity,
                &serialize(&public.t),
                &serialize(&public.gamma),
                &serialize(&self.p_public),
            ],
        )
    }

    fn message_hash(
        &self,
        c_delta: &Projective,
        sender: &PublicKey,
        session_point: &Projective,
        message: &[u8; 32],
    ) -> Fr {
        hash_nonzero_scalar(
            b"Gao25/H5",
            &[
                &serialize(c_delta),
                &sender.identity,
                &serialize(&sender.t),
                &serialize(&sender.gamma),
                &serialize(session_point),
                message,
            ],
        )
    }
}

fn interpolate_group(columns: &[Vec<Fr>], values: &[Projective]) -> Vec<Projective> {
    assert_eq!(columns.len(), values.len());
    assert!(columns.iter().all(|column| column.len() == values.len()));
    let bases = values
        .iter()
        .map(|point| point.into_affine())
        .collect::<Vec<_>>();
    columns
        .iter()
        .map(|column| Projective::msm_unchecked(&bases, column))
        .collect()
}

/// Returns columns of the Lagrange interpolation matrix in ascending order.
fn lagrange_columns(xs: &[Fr]) -> Vec<Vec<Fr>> {
    assert!(!xs.is_empty());
    for i in 0..xs.len() {
        assert!(!xs[..i].contains(&xs[i]), "H2 identity collision");
    }

    let mut product = vec![Fr::from(1u64)];
    for x in xs {
        let mut next = vec![Fr::zero(); product.len() + 1];
        for (degree, coefficient) in product.iter().enumerate() {
            next[degree] -= *coefficient * x;
            next[degree + 1] += coefficient;
        }
        product = next;
    }

    let count = xs.len();
    let mut columns = vec![vec![Fr::zero(); count]; count];
    for (point, x) in xs.iter().enumerate() {
        let mut quotient = vec![Fr::zero(); count];
        quotient[count - 1] = product[count];
        for degree in (1..count).rev() {
            quotient[degree - 1] = product[degree] + *x * quotient[degree];
        }
        let denominator = quotient
            .iter()
            .rev()
            .fold(Fr::zero(), |value, coefficient| value * x + coefficient);
        let inverse = denominator
            .inverse()
            .expect("distinct interpolation points");
        for degree in 0..count {
            columns[degree][point] = quotient[degree] * inverse;
        }
    }
    columns
}

fn scalar_powers(x: Fr, count: usize) -> Vec<Fr> {
    let mut powers = Vec::with_capacity(count);
    let mut value = Fr::from(1u64);
    for _ in 0..count {
        powers.push(value);
        value *= x;
    }
    powers
}

fn hash_nonzero_scalar(domain: &[u8], chunks: &[&[u8]]) -> Fr {
    let mut scalar = Fr::from_be_bytes_mod_order(&hash_bytes(domain, chunks));
    if scalar.is_zero() {
        scalar = Fr::from(1u64);
    }
    scalar
}

fn hash_to_group(domain: &[u8], chunks: &[&[u8]]) -> Projective {
    // The article models H3 as a random oracle into the P-256 group but does
    // not prescribe an encoding. Try-and-increment gives a deterministic
    // full-domain-style map whose output has no known discrete logarithm.
    // P-256 has cofactor one, so every affine curve point is in the prime-order
    // subgroup used by the construction.
    for counter in 0u64.. {
        let counter_bytes = counter.to_le_bytes();
        let mut hash_chunks = chunks.to_vec();
        hash_chunks.push(&counter_bytes);
        let digest = hash_bytes(domain, &hash_chunks);
        let x = Fq::from_be_bytes_mod_order(&digest);
        let rhs = x.square() * x + Config::COEFF_A * x + Config::COEFF_B;
        if let Some(mut y) = rhs.sqrt() {
            let requested_odd = digest[0] & 1 == 1;
            if y.into_bigint().is_odd() != requested_odd {
                y = -y;
            }
            return Affine::new_unchecked(x, y).into_group();
        }
    }
    unreachable!("a P-256 square root is found with overwhelming probability")
}

fn random_nonzero(rng: &mut impl RngCore) -> Fr {
    loop {
        let value = Fr::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn signcrypt_revoke_and_unsigncrypt() {
        let mut rng = StdRng::seed_from_u64(121540);
        let scheme = Gao25::setup(8, &mut rng);
        let sender = scheme.register(b"base-station", &mut rng);
        let recipients = (0..8)
            .map(|i| scheme.register(format!("ecn-{i}").as_bytes(), &mut rng))
            .collect::<Vec<_>>();
        let public = recipients
            .iter()
            .map(|user| user.public.clone())
            .collect::<Vec<_>>();
        let message = [0x25u8; 32];

        let signcrypt_cache = scheme.prepare_signcrypt(&sender.public, &public);
        let ciphertext = scheme.signcrypt_cached(&sender, &signcrypt_cache, &message, &mut rng);
        for receiver in &recipients {
            assert_eq!(
                scheme.unsigncrypt(receiver, &sender.public, &ciphertext),
                Some(message)
            );
        }

        let authorized = public[..4].to_vec();
        let revocation_cache = scheme.prepare_revocation(&signcrypt_cache, &authorized);
        let reduced = scheme.revoke_cached(&ciphertext, &revocation_cache);
        for receiver in &recipients[..4] {
            assert_eq!(
                scheme.unsigncrypt(receiver, &sender.public, &reduced),
                Some(message)
            );
        }
        for receiver in &recipients[4..] {
            assert_eq!(scheme.unsigncrypt(receiver, &sender.public, &reduced), None);
        }

        let mut modified = reduced.clone();
        modified.c_message[0] ^= 1;
        assert_eq!(
            scheme.unsigncrypt(&recipients[0], &sender.public, &modified),
            None
        );
    }

    #[test]
    fn lagrange_matrix_recovers_values() {
        let xs = [Fr::from(2u64), Fr::from(5u64), Fr::from(9u64)];
        let columns = lagrange_columns(&xs);
        let values = [
            Projective::generator() * Fr::from(7u64),
            Projective::generator() * Fr::from(11u64),
            Projective::generator() * Fr::from(23u64),
        ];
        let coefficients = interpolate_group(&columns, &values);
        for (x, expected) in xs.iter().zip(values.iter()) {
            let powers = scalar_powers(*x, coefficients.len());
            let bases = coefficients
                .iter()
                .map(|point| point.into_affine())
                .collect::<Vec<_>>();
            assert_eq!(Projective::msm_unchecked(&bases, &powers), *expected);
        }
    }

    #[test]
    fn h3_maps_to_valid_unknown_discrete_log_points() {
        let first = hash_to_group(b"Gao25/H3", &[b"ecn-1", b"context"]);
        let second = hash_to_group(b"Gao25/H3", &[b"ecn-2", b"context"]);
        assert!(!first.is_zero());
        assert!(!second.is_zero());
        assert_ne!(first, second);
        assert!(first.into_affine().is_on_curve());
        assert!(first
            .into_affine()
            .is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn ciphertext_and_secret_key_use_canonical_serialization() {
        let mut rng = StdRng::seed_from_u64(25);
        let scheme = Gao25::setup(4, &mut rng);
        let sender = scheme.register(b"sender", &mut rng);
        let recipients = (0..4)
            .map(|i| scheme.register(format!("receiver-{i}").as_bytes(), &mut rng))
            .collect::<Vec<_>>();
        let public = recipients
            .iter()
            .map(|user| user.public.clone())
            .collect::<Vec<_>>();
        let ciphertext = scheme.signcrypt(&sender, &public, &[7u8; 32], &mut rng);
        assert_eq!(ciphertext.serialized_bytes().len(), 33 * public.len() + 130);
        assert_eq!(sender.serialized_bytes().len(), 64);
    }
}
