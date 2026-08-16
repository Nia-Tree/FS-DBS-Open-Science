//! Selvi et al. (IACR ePrint 2008/341, revised 2009) multi-receiver
//! identity-based signcryption.
//!
//! This is the construction in Section 2.5. The source paper uses a symmetric
//! pairing. Its equations admit the following Type-3 placement without a
//! source-group isomorphism: `P`, `R`, user private keys, `X`, and `Z_A` are
//! in G1; `Q`, its powers, and `y` are in G2.

use crate::common::{
    hash_to_scalar, hash_to_scalar_excluding, kdf_expand_gt, pairing, pairing_product,
    random_nonzero_scalar, serialize, Scalar, G1, G2, GT,
};
use ark_ec::PrimeGroup;
use ark_ff::{Field, Zero};
use ark_serialize::CanonicalDeserialize;
use rand::RngCore;

#[derive(Clone)]
pub struct IdentityPublicKey {
    pub identity: Vec<u8>,
    pub h1: Scalar,
}

#[derive(Clone)]
pub struct IdentityKey {
    pub public: IdentityPublicKey,
    secret: G1,
}

impl IdentityKey {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        serialize(&self.secret)
    }
}

#[derive(Clone)]
pub struct RecipientCache {
    identities: Vec<Vec<u8>>,
    y_base: G2,
    f_points: Vec<G2>,
    denominator_inverses: Vec<Option<Scalar>>,
}

#[derive(Clone)]
pub struct Ciphertext {
    x: G1,
    y: G2,
    encrypted_body: Vec<u8>,
}

impl Ciphertext {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = serialize(&self.x);
        bytes.extend_from_slice(&serialize(&self.y));
        bytes.extend_from_slice(&self.encrypted_body);
        bytes
    }
}

pub struct Selvi09 {
    max_receivers: usize,
    p: G1,
    q: G2,
    r_public: G1,
    s_q: G2,
    s_powers_q: Vec<G2>,
    target_base: GT,
    master_s: Scalar,
}

impl Selvi09 {
    pub fn setup(max_receivers: usize, rng: &mut impl RngCore) -> Self {
        let p = G1::generator();
        let q = G2::generator();
        let master_s = random_nonzero_scalar(rng);
        let mut scalar_power = Scalar::from(1u64);
        let mut s_powers_q = Vec::with_capacity(max_receivers + 1);
        for _ in 0..=max_receivers {
            s_powers_q.push(q * scalar_power);
            scalar_power *= master_s;
        }
        Self {
            max_receivers,
            p,
            q,
            r_public: p * master_s,
            s_q: q * master_s,
            s_powers_q,
            target_base: pairing(p, q),
            master_s,
        }
    }

    pub fn extract(&self, identity: &[u8]) -> IdentityKey {
        let h1 = hash_to_scalar_excluding(
            b"Selvi09/H1",
            &[identity],
            &[Scalar::zero(), -self.master_s],
        );
        let inverse = (h1 + self.master_s)
            .inverse()
            .expect("excluded zero denominator");
        IdentityKey {
            public: IdentityPublicKey {
                identity: identity.to_vec(),
                h1,
            },
            secret: self.p * inverse,
        }
    }

    pub fn prepare_recipients(&self, recipients: &[IdentityPublicKey]) -> RecipientCache {
        self.prepare_recipients_internal(recipients, None, true)
    }

    pub fn prepare_encrypt_recipients(&self, recipients: &[IdentityPublicKey]) -> RecipientCache {
        self.prepare_recipients_internal(recipients, Some(usize::MAX), true)
    }

    pub fn prepare_receiver(
        &self,
        recipients: &[IdentityPublicKey],
        receiver_position: usize,
    ) -> RecipientCache {
        assert!(receiver_position < recipients.len());
        self.prepare_recipients_internal(recipients, Some(receiver_position), false)
    }

    fn prepare_recipients_internal(
        &self,
        recipients: &[IdentityPublicKey],
        only_position: Option<usize>,
        include_encrypt_base: bool,
    ) -> RecipientCache {
        assert!(!recipients.is_empty() && recipients.len() <= self.max_receivers);
        let h_values = recipients.iter().map(|r| r.h1).collect::<Vec<_>>();
        let polynomial = product_polynomial(&h_values);
        let y_base = if include_encrypt_base {
            evaluate_public_polynomial(&polynomial, &self.s_powers_q)
        } else {
            G2::zero()
        };
        let mut f_points = Vec::with_capacity(recipients.len());
        let mut denominator_inverses = Vec::with_capacity(recipients.len());
        for (position, receiver) in recipients.iter().enumerate() {
            if only_position.is_some() && only_position != Some(position) {
                f_points.push(G2::zero());
                denominator_inverses.push(None);
                continue;
            }
            let quotient = divide_by_linear(&polynomial, receiver.h1);
            let denominator_inverse = quotient[0]
                .inverse()
                .expect("H1 outputs are non-zero with overwhelming probability");
            // (prod_{j != i}(s+h_j) - prod_{j != i}h_j) / s
            let f_coefficients = if quotient.len() > 1 {
                quotient[1..].to_vec()
            } else {
                vec![Scalar::zero()]
            };
            f_points.push(evaluate_public_polynomial(
                &f_coefficients,
                &self.s_powers_q,
            ));
            denominator_inverses.push(Some(denominator_inverse));
        }
        RecipientCache {
            identities: recipients.iter().map(|r| r.identity.clone()).collect(),
            y_base,
            f_points,
            denominator_inverses,
        }
    }

    pub fn signcrypt_cached(
        &self,
        sender: &IdentityKey,
        recipients: &RecipientCache,
        key: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Ciphertext {
        let r = random_nonzero_scalar(rng);
        let alpha = self.target_base * r;
        let h = h2(key, &alpha);
        let z_a = sender.secret * (r + h);
        let mut body = Vec::with_capacity(32 + 48);
        body.extend_from_slice(key);
        body.extend_from_slice(&serialize(&z_a));
        let pad = kdf_expand_gt(b"Selvi09/H3", &alpha, body.len());
        for (byte, mask) in body.iter_mut().zip(pad) {
            *byte ^= mask;
        }
        let _ = &recipients.identities;
        Ciphertext {
            x: -(self.r_public * r),
            y: recipients.y_base * r,
            encrypted_body: body,
        }
    }

    pub fn designcrypt_cached(
        &self,
        receiver_position: usize,
        receiver: &IdentityKey,
        sender: &IdentityPublicKey,
        recipients: &RecipientCache,
        ciphertext: &Ciphertext,
    ) -> Option<[u8; 32]> {
        if recipients.identities.get(receiver_position)? != &receiver.public.identity {
            return None;
        }
        let inverse = recipients.denominator_inverses[receiver_position]?;
        let alpha = pairing_product(&[
            (receiver.secret, ciphertext.y),
            (ciphertext.x, recipients.f_points[receiver_position]),
        ]) * inverse;
        let pad = kdf_expand_gt(b"Selvi09/H3", &alpha, ciphertext.encrypted_body.len());
        let mut body = ciphertext.encrypted_body.clone();
        for (byte, mask) in body.iter_mut().zip(pad) {
            *byte ^= mask;
        }
        if body.len() < 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&body[..32]);
        let z_a = G1::deserialize_compressed(&body[32..]).ok()?;
        let h = h2(&key, &alpha);
        let verification = pairing(z_a, self.s_q + self.q * sender.h1) - self.target_base * h;
        if verification != alpha {
            return None;
        }
        Some(key)
    }
}

fn h2(message: &[u8; 32], alpha: &GT) -> Scalar {
    let alpha_bytes = serialize(alpha);
    hash_to_scalar(b"Selvi09/H2", &[message, &alpha_bytes])
}

fn product_polynomial(shifts: &[Scalar]) -> Vec<Scalar> {
    let mut coefficients = vec![Scalar::from(1u64)];
    for shift in shifts {
        let mut next = vec![Scalar::zero(); coefficients.len() + 1];
        for (degree, coefficient) in coefficients.iter().enumerate() {
            next[degree] += *coefficient * shift;
            next[degree + 1] += coefficient;
        }
        coefficients = next;
    }
    coefficients
}

fn divide_by_linear(polynomial: &[Scalar], shift: Scalar) -> Vec<Scalar> {
    assert!(polynomial.len() >= 2);
    let degree = polynomial.len() - 1;
    let mut quotient = vec![Scalar::zero(); degree];
    quotient[degree - 1] = polynomial[degree];
    for k in (1..degree).rev() {
        quotient[k - 1] = polynomial[k] - shift * quotient[k];
    }
    debug_assert_eq!(polynomial[0], shift * quotient[0]);
    quotient
}

fn evaluate_public_polynomial(coefficients: &[Scalar], powers: &[G2]) -> G2 {
    coefficients
        .iter()
        .zip(powers)
        .fold(G2::zero(), |acc, (coefficient, point)| {
            acc + *point * coefficient
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn type3_round_trip_and_authentication() {
        let mut rng = StdRng::seed_from_u64(2009);
        let scheme = Selvi09::setup(16, &mut rng);
        let sender = scheme.extract(b"model-provider");
        let receivers = (0..8)
            .map(|i| scheme.extract(format!("edge-{i}").as_bytes()))
            .collect::<Vec<_>>();
        let public = receivers
            .iter()
            .map(|receiver| receiver.public.clone())
            .collect::<Vec<_>>();
        let cache = scheme.prepare_recipients(&public);
        let key = [0x55u8; 32];
        let ciphertext = scheme.signcrypt_cached(&sender, &cache, &key, &mut rng);
        assert_eq!(
            scheme.designcrypt_cached(3, &receivers[3], &sender.public, &cache, &ciphertext),
            Some(key)
        );
        let mut tampered = ciphertext.clone();
        tampered.encrypted_body[0] ^= 1;
        assert!(scheme
            .designcrypt_cached(3, &receivers[3], &sender.public, &cache, &tampered)
            .is_none());
        assert_eq!(ciphertext.serialized_bytes().len(), 224);
        assert_eq!(receivers[3].serialized_bytes().len(), 48);
    }
}
