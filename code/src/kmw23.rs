//! KMW23 distributed broadcast encryption from asymmetric bilinear groups.
//!
//! Paper and equation mapping:
//! - Kolonelos, Malavolta, and Wee, ASIACRYPT 2023, Section 5.1.
//! - Garg, Lu, Waters, and Wu, ePrint 2023/1583, Construction A.7.
//! - [`Kmw23::setup`] implements Eq. (A.1).
//! - [`Kmw23::keygen`] implements Construction A.7 `KeyGen`.
//! - [`Kmw23::encrypt_cached`] implements Construction A.7 `Encrypt` as a
//!   32-byte KEM projection: `Z^s` is passed through a domain-separated KDF and
//!   XORs the content key, in the same role as the source component
//!   `C1 = m * Z^s`. Components `C2` and `C3` are unchanged.
//! - [`Kmw23::decrypt_cached`] implements the inverse of the two pairing terms
//!   in Construction A.7 `Decrypt` to reconstruct `Z^s`.
//!
//! Construction A.7 moves the public cross terms to G1 for asymmetric groups;
//! this is the orientation used here on BLS12-381.

use crate::common::{
    alpha_powers, kdf_gt, pairing, pairing_product, random_nonzero_scalar, serialize, xor32,
    Scalar, G1, G2, GT,
};
use ark_ec::PrimeGroup;
use ark_ff::Zero;
use rand::RngCore;

#[derive(Clone)]
pub struct UserPublicKey {
    pub index: usize,
    t: G1,
    cross: Vec<G1>,
}

#[derive(Clone)]
pub struct UserSecretKey {
    pub index: usize,
    value: G1,
}

impl UserSecretKey {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.index as u64).to_le_bytes());
        bytes.extend_from_slice(&serialize(&self.value));
        bytes
    }
}

#[derive(Clone)]
pub struct User {
    pub public: UserPublicKey,
    pub secret: UserSecretKey,
}

#[derive(Clone)]
pub struct RecipientCache {
    pub recipients: Vec<usize>,
    encrypt_base: G1,
    receiver_terms: Vec<Option<G1>>,
}

#[derive(Clone)]
pub struct Ciphertext {
    pub c2: G2,
    pub c3: G1,
    pub wrapped_key: [u8; 32],
}

impl Ciphertext {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&serialize(&self.c2));
        bytes.extend_from_slice(&serialize(&self.c3));
        bytes.extend_from_slice(&self.wrapped_key);
        bytes
    }
}

pub struct Kmw23 {
    n: usize,
    g1: G1,
    g2: G2,
    a: Vec<G1>,
    b: Vec<G2>,
    powers: Vec<Scalar>,
    target_base: GT,
}

impl Kmw23 {
    pub fn setup(n: usize, rng: &mut impl RngCore) -> Self {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let alpha = random_nonzero_scalar(rng);
        let powers = alpha_powers(alpha, 2 * n + 1);
        let mut a = powers.iter().map(|x| g1 * x).collect::<Vec<_>>();
        a[n + 1] = G1::zero();
        // B_1,...,B_N are public in Eq. (A.1). B_0 is retained internally as
        // the generator to preserve direct exponent indexing.
        let b = powers[..=n].iter().map(|x| g2 * x).collect::<Vec<_>>();
        let target_base = pairing(a[1], b[n]);
        Self {
            n,
            g1,
            g2,
            a,
            b,
            powers,
            target_base,
        }
    }

    pub fn keygen(&self, index: usize, rng: &mut impl RngCore) -> User {
        assert!((1..=self.n).contains(&index));
        let r = random_nonzero_scalar(rng);
        let secret_index = self.n + 1 - index;
        let mut cross = vec![G1::zero(); self.n + 1];
        for (j, value) in cross.iter_mut().enumerate().take(self.n + 1).skip(1) {
            if j != secret_index {
                *value = self.a[j] * r;
            }
        }
        User {
            public: UserPublicKey {
                index,
                t: self.g1 * r,
                cross,
            },
            secret: UserSecretKey {
                index,
                value: self.g1 * (r * self.powers[secret_index]),
            },
        }
    }

    pub fn prepare_recipients(
        &self,
        recipients: &[usize],
        public_keys: &[UserPublicKey],
        secret_keys: &[UserSecretKey],
    ) -> RecipientCache {
        let mut cache = self.prepare_encrypt_recipients(recipients, public_keys);
        for &receiver in recipients {
            self.add_receiver_context(
                &mut cache,
                receiver,
                public_keys,
                &secret_keys[receiver - 1],
            );
        }
        cache
    }

    pub fn prepare_encrypt_recipients(
        &self,
        recipients: &[usize],
        public_keys: &[UserPublicKey],
    ) -> RecipientCache {
        let mut encrypt_base = G1::zero();
        for &i in recipients {
            encrypt_base += public_keys[i - 1].t + self.a[i];
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
        public_keys: &[UserPublicKey],
        secret_key: &UserSecretKey,
    ) {
        assert!(cache.recipients.contains(&receiver));
        let mut term = secret_key.value;
        let cross_index = self.n + 1 - receiver;
        for &i in &cache.recipients {
            if i != receiver {
                term += public_keys[i - 1].cross[cross_index] + self.a[self.n + 1 + i - receiver];
            }
        }
        cache.receiver_terms[receiver] = Some(term);
    }

    pub fn encrypt_cached(
        &self,
        recipients: &RecipientCache,
        key: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Ciphertext {
        let s = random_nonzero_scalar(rng);
        let session = self.target_base * s;
        Ciphertext {
            c2: self.g2 * s,
            c3: recipients.encrypt_base * s,
            wrapped_key: xor32(key, &kdf_gt(b"KMW23/KEM", &session)),
        }
    }

    pub fn decrypt_cached(
        &self,
        receiver: usize,
        recipients: &RecipientCache,
        ciphertext: &Ciphertext,
    ) -> Option<[u8; 32]> {
        let term = recipients
            .receiver_terms
            .get(receiver)
            .and_then(|entry| *entry)?;
        let session = pairing_product(&[
            (ciphertext.c3, self.b[self.n + 1 - receiver]),
            (-term, ciphertext.c2),
        ]);
        Some(xor32(
            &ciphertext.wrapped_key,
            &kdf_gt(b"KMW23/KEM", &session),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn round_trip() {
        let mut rng = StdRng::seed_from_u64(23);
        let scheme = Kmw23::setup(16, &mut rng);
        let users = (1..=16)
            .map(|i| scheme.keygen(i, &mut rng))
            .collect::<Vec<_>>();
        let pks = users.iter().map(|u| u.public.clone()).collect::<Vec<_>>();
        let sks = users.iter().map(|u| u.secret.clone()).collect::<Vec<_>>();
        let cache = scheme.prepare_recipients(&[1, 4, 7, 9, 16], &pks, &sks);
        let key = [9u8; 32];
        let ciphertext = scheme.encrypt_cached(&cache, &key, &mut rng);
        assert_eq!(scheme.decrypt_cached(7, &cache, &ciphertext), Some(key));
        assert_eq!(scheme.decrypt_cached(2, &cache, &ciphertext), None);
    }
}


// Diagnostic receiver-specific fixture only. All original online methods remain unchanged.
impl Kmw23 {
    pub fn quick_receiver_fixture_keygen(&self, index: usize, receiver: usize, rng: &mut impl RngCore) -> User {
        assert!((1..=self.n).contains(&index));
        assert!((1..=self.n).contains(&receiver));
        let r = random_nonzero_scalar(rng);
        let secret_index = self.n + 1 - index;
        let cross_index = self.n + 1 - receiver;
        let mut cross = vec![G1::zero(); self.n + 1];
        if cross_index != secret_index { cross[cross_index] = self.a[cross_index] * r; }
        User {
            public: UserPublicKey { index, t: self.g1 * r, cross },
            secret: UserSecretKey { index, value: self.g1 * (r * self.powers[secret_index]) },
        }
    }

    pub fn assert_quick_fixture_fields_equal(&self, projected: &User, full: &User, receiver: usize) {
        assert_eq!(projected.public.index, full.public.index);
        assert_eq!(projected.public.t, full.public.t);
        assert_eq!(projected.public.cross.len(), self.n + 1);
        assert_eq!(projected.public.cross.len(), full.public.cross.len());
        let cross_index = self.n + 1 - receiver;
        assert_eq!(projected.public.cross[cross_index], full.public.cross[cross_index]);
        assert_eq!(projected.secret.serialized_bytes(), full.secret.serialized_bytes());
    }
}
