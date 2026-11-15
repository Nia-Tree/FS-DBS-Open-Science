use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub type G1 = G1Projective;
pub type G2 = G2Projective;
pub type GT = ark_ec::pairing::PairingOutput<Bls12_381>;
pub type Scalar = Fr;

// Store the base and use ordinary scalar multiplication.
#[derive(Clone)]
pub struct FixedBaseTable<G>
where G: PrimeGroup<ScalarField = Scalar> + Copy,
{ base: G }

impl<G> FixedBaseTable<G>
where G: PrimeGroup<ScalarField = Scalar> + Copy,
{
    pub fn new(base:G)->Self {Self{base}}
    pub fn mul(&self,scalar:Scalar)->G {self.base*scalar}
    pub fn element_count(&self)->usize {1}
    pub fn estimated_group_ram_bytes(&self)->usize {std::mem::size_of::<G>()}
}

pub fn pairing(a: G1, b: G2) -> GT {
    Bls12_381::pairing(a.into_affine(), b.into_affine())
}

pub fn pairing_product(pairs: &[(G1, G2)]) -> GT {
    let g1 = pairs
        .iter()
        .map(|(left, _)| left.into_affine())
        .collect::<Vec<_>>();
    let g2 = pairs
        .iter()
        .map(|(_, right)| right.into_affine())
        .collect::<Vec<_>>();
    Bls12_381::multi_pairing(g1, g2)
}

pub fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    Scalar::rand(rng)
}

pub fn random_nonzero_scalar(rng: &mut impl RngCore) -> Scalar {
    loop {
        let value = random_scalar(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

pub fn serialize<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("serialization into Vec cannot fail");
    bytes
}

pub fn hash_bytes(domain: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((domain.len() as u64).to_le_bytes());
    hash.update(domain);
    for chunk in chunks {
        hash.update((chunk.len() as u64).to_le_bytes());
        hash.update(chunk);
    }
    hash.finalize().into()
}

pub fn hash_to_scalar(domain: &[u8], chunks: &[&[u8]]) -> Scalar {
    Scalar::from_be_bytes_mod_order(&hash_bytes(domain, chunks))
}

pub fn hash_to_scalar_excluding(domain: &[u8], chunks: &[&[u8]], excluded: &[Scalar]) -> Scalar {
    let mut counter = 0u64;
    loop {
        let counter_bytes = counter.to_le_bytes();
        let mut with_counter = chunks.to_vec();
        with_counter.push(&counter_bytes);
        let candidate = hash_to_scalar(domain, &with_counter);
        if !excluded.contains(&candidate) {
            return candidate;
        }
        counter += 1;
    }
}

pub fn kdf_gt(domain: &[u8], value: &GT) -> [u8; 32] {
    let encoded = serialize(value);
    hash_bytes(domain, &[&encoded])
}

pub fn kdf_expand_gt(domain: &[u8], value: &GT, length: usize) -> Vec<u8> {
    let encoded = serialize(value);
    let mut out = Vec::with_capacity(length);
    let mut counter = 0u64;
    while out.len() < length {
        let counter_bytes = counter.to_le_bytes();
        out.extend_from_slice(&hash_bytes(domain, &[&encoded, &counter_bytes]));
        counter += 1;
    }
    out.truncate(length);
    out
}

pub fn xor32(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = left[i] ^ right[i];
    }
    out
}

pub fn encode_indices(indices: &[usize]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(indices.len() * 8);
    for index in indices {
        bytes.extend_from_slice(&(*index as u64).to_le_bytes());
    }
    bytes
}

pub fn encode_scalars(values: &[Scalar]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        value
            .serialize_compressed(&mut bytes)
            .expect("serialization into Vec cannot fail");
    }
    bytes
}

pub fn alpha_powers(alpha: Scalar, max_power: usize) -> Vec<Scalar> {
    let mut powers = vec![Scalar::from(1u64); max_power + 1];
    for i in 1..=max_power {
        powers[i] = powers[i - 1] * alpha;
    }
    powers
}
