//! AFI06-CCA: BasicHICBE2 with the CHK transform.
//!
//! BasicHICBE2 reserves identity level d+1 for H(vk), where vk is freshly generated
//! for each ciphertext. A time identity of length <=d is padded with zero labels
//! before that final level; binary time labels are 1/2. Ed25519 is used internally
//! as a strong one-time signature, never as a long-term sender identity signature.
//! The signature and KDF bind the setup, canonical recipient set, exact time path,
//! one-time verification key, and all three header coordinates; the signature
//! also binds the wrapped 32-byte payload. Strict signature verification is used.
//!
//! Receiver delegation at the reserved level uses delta=0 internally. No derived
//! key is released, so a0'=a0+b_last*H(vk), a1'=a1 suffice. The time state retains
//! the complete future preorder frontier, with no signature levels in that tree.

use crate::afi06::{Afi06, Ciphertext as CoreCiphertext, ForwardSecureState};
use crate::common::{encode_indices, hash_bytes, hash_to_scalar_excluding, Scalar};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;

pub struct State {
    inner: Option<ForwardSecureState>,
    binding: [u8; 32],
}

impl State {
    fn from_inner(inner: ForwardSecureState) -> Self {
        let binding = hash_bytes(b"AFI06-CHK/state-binding/v1", &[&inner.current().serialized_bytes()]);
        Self { inner: Some(inner), binding }
    }

    pub fn current_node(&self) -> &[u8] {
        &self.inner.as_ref().expect("state is exhausted").current().node
    }

    pub fn receiver_index(&self) -> usize {
        self.inner.as_ref().expect("state is exhausted").current().index
    }

    pub fn is_exhausted(&self) -> bool { self.inner.is_none() }

    pub fn number_of_g2_elements(&self) -> usize {
        self.inner.as_ref().map_or(0, ForwardSecureState::number_of_g2_elements)
    }

    pub fn serialized_bytes(&self) -> Vec<u8> {
        self.inner.as_ref().map_or_else(Vec::new, ForwardSecureState::serialized_bytes)
    }
}

#[derive(Clone)]
pub struct TimeCache {
    inner: crate::afi06::TimeCache,
}

impl TimeCache {
    pub fn node(&self) -> &[u8] { &self.inner.node }
}

pub struct RecipientCache {
    inner: crate::afi06::RecipientCache,
    recipients: Vec<usize>,
    encoded: Vec<u8>,
    receiver_bindings: Vec<(usize, [u8; 32])>,
    encrypt_ready: bool,
}

#[derive(Clone)]
pub struct Ciphertext {
    header: CoreCiphertext,
    verification_key: [u8; 32],
    signature: [u8; 64],
}

impl Ciphertext {
    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut out = self.header.serialized_bytes();
        out.extend_from_slice(&self.verification_key);
        out.extend_from_slice(&self.signature);
        out
    }
}

pub struct Afi06Cca {
    core: Afi06,
    n: usize,
    period_depth: usize,
    parameter_id: [u8; 32],
}

impl Afi06Cca {
    pub fn setup(n: usize, period_depth: usize, rng: &mut impl RngCore) -> Self {
        let core = Afi06::setup(n, period_depth + 1, rng);
        let parameter_id = core.parameter_fingerprint();
        Self { core, n, period_depth, parameter_id }
    }

    pub fn initial_state(&self, receiver: usize, rng: &mut impl RngCore) -> State {
        State::from_inner(self.core.initial_state(receiver, rng))
    }

    /// node contains labels 1/2, matching Afi06::UserKey::node and FS-DBS nodes.
    pub fn state_at_node(&self, receiver: usize, node: &[u8], rng: &mut impl RngCore) -> State {
        State::from_inner(self.core.state_at_node_limited(receiver, node, self.period_depth, rng))
    }

    /// Consumes the old logical state. False means that the final period was left.
    /// Previously prepared receiver caches must be discarded and rebuilt.
    pub fn advance_state(&self, state: &mut State, rng: &mut impl RngCore) -> bool {
        let Some(old) = state.inner.take() else { return false; };
        let next = self.core.update_state_limited(&old, self.period_depth, rng);
        state.binding = [0; 32];
        if let Some(next) = next {
            *state = State::from_inner(next);
            true
        } else {
            false
        }
    }

    pub fn prepare_time(&self, node: &[u8]) -> TimeCache {
        assert!(node.len() <= self.period_depth);
        assert!(node.iter().all(|label| *label == 1 || *label == 2));
        TimeCache { inner: self.core.prepare_time(node) }
    }

    fn validate_recipients(&self, recipients: &[usize]) {
        assert!(!recipients.is_empty());
        assert!(recipients.iter().all(|j| (1..=self.n).contains(j)));
        assert!(recipients.windows(2).all(|pair| pair[0] < pair[1]), "recipient set must be sorted and unique");
    }

    pub fn prepare_encrypt_recipients(&self, recipients: &[usize]) -> RecipientCache {
        self.validate_recipients(recipients);
        RecipientCache {
            inner: self.core.prepare_encrypt_recipients(recipients),
            recipients: recipients.to_vec(), encoded: encode_indices(recipients),
            receiver_bindings: Vec::new(), encrypt_ready: true,
        }
    }

    pub fn prepare_receiver_recipients(&self, recipients: &[usize]) -> RecipientCache {
        self.validate_recipients(recipients);
        RecipientCache {
            inner: self.core.prepare_receiver_recipients(recipients),
            recipients: recipients.to_vec(), encoded: encode_indices(recipients),
            receiver_bindings: Vec::new(), encrypt_ready: false,
        }
    }

    pub fn add_receiver_context(&self, cache: &mut RecipientCache, receiver: usize, state: &State) {
        let key = state.inner.as_ref().expect("state is exhausted").current();
        assert_eq!(receiver, key.index);
        self.core.add_receiver_context(&mut cache.inner, receiver, key);
        cache.receiver_bindings.retain(|(index, _)| *index != receiver);
        cache.receiver_bindings.push((receiver, state.binding));
    }

    fn context(&self, recipients: &RecipientCache, time: &TimeCache, vk: &[u8; 32]) -> Vec<u8> {
        let mut context = Vec::with_capacity(104 + recipients.encoded.len() + time.node().len());
        context.extend_from_slice(b"AFI06-CHK/context/v1");
        context.extend_from_slice(&self.parameter_id);
        context.extend_from_slice(&(recipients.recipients.len() as u64).to_le_bytes());
        context.extend_from_slice(&recipients.encoded);
        context.extend_from_slice(&(time.node().len() as u64).to_le_bytes());
        context.extend_from_slice(time.node());
        context.extend_from_slice(vk);
        context
    }

    fn verification_identity(vk: &[u8; 32]) -> Scalar {
        hash_to_scalar_excluding(b"AFI06-CHK/final-identity/v1", &[vk], &[Scalar::from(0u64)])
    }

    fn signed_message(context: &[u8], header: &CoreCiphertext) -> Vec<u8> {
        let mut message = context.to_vec();
        message.extend_from_slice(&header.serialized_bytes());
        message
    }

    pub fn encrypt_cached(
        &self, recipients: &RecipientCache, time: &TimeCache,
        key: &[u8; 32], rng: &mut impl RngCore,
    ) -> Ciphertext {
        assert!(recipients.encrypt_ready);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verification_key = signing_key.verifying_key().to_bytes();
        let context = self.context(recipients, time, &verification_key);
        let identity = Self::verification_identity(&verification_key);
        let header = self.core.encrypt_chk_cached(&recipients.inner, &time.inner, identity, &context, key, rng);
        let signature = signing_key.sign(&Self::signed_message(&context, &header)).to_bytes();
        Ciphertext { header, verification_key, signature }
    }

    pub fn decrypt_cached(
        &self, receiver: usize, state: &State, recipients: &RecipientCache,
        time: &TimeCache, ciphertext: &Ciphertext,
    ) -> Option<[u8; 32]> {
        let key = state.inner.as_ref()?.current();
        if key.index != receiver || key.node != time.inner.node
            || !recipients.receiver_bindings.contains(&(receiver, state.binding)) {
            return None;
        }
        let verification_key = VerifyingKey::from_bytes(&ciphertext.verification_key).ok()?;
        let context = self.context(recipients, time, &ciphertext.verification_key);
        let signature = ed25519_dalek::Signature::from_bytes(&ciphertext.signature);
        verification_key.verify_strict(&Self::signed_message(&context, &ciphertext.header), &signature).ok()?;
        self.core.decrypt_chk_cached(receiver, key, &recipients.inner, &time.inner,
            Self::verification_identity(&ciphertext.verification_key), &context, &ciphertext.header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::G1;
    use ark_ec::PrimeGroup;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn round_trip_multiple_users_and_every_ciphertext_component() {
        let mut rng = StdRng::seed_from_u64(0xAF10_CCA1);
        let scheme = Afi06Cca::setup(16, 3, &mut rng);
        let node = [1, 2, 1];
        let time = scheme.prepare_time(&node);
        let enc = scheme.prepare_encrypt_recipients(&[1, 3, 7]);
        let mut dec = scheme.prepare_receiver_recipients(&[1, 3, 7]);
        let states: Vec<_> = [1, 3, 7].iter().map(|j| scheme.state_at_node(*j, &node, &mut rng)).collect();
        for state in &states { scheme.add_receiver_context(&mut dec, state.receiver_index(), state); }
        let message = [0x42; 32];
        let ciphertext = scheme.encrypt_cached(&enc, &time, &message, &mut rng);
        assert_eq!(ciphertext.serialized_bytes().len(), 272);
        for state in &states {
            assert_eq!(scheme.decrypt_cached(state.receiver_index(), state, &dec, &time, &ciphertext), Some(message));
        }
        let rejected = |ct: &Ciphertext| assert!(scheme.decrypt_cached(1, &states[0], &dec, &time, ct).is_none());
        let mut ct = ciphertext.clone(); ct.header.c0 += G1::generator(); rejected(&ct);
        let mut ct = ciphertext.clone(); ct.header.c1 += G1::generator(); rejected(&ct);
        let mut ct = ciphertext.clone(); ct.header.c2 += G1::generator(); rejected(&ct);
        let mut ct = ciphertext.clone(); ct.header.wrapped_key[0] ^= 1; rejected(&ct);
        let mut ct = ciphertext.clone(); ct.verification_key[0] ^= 1; rejected(&ct);
        let mut ct = ciphertext.clone(); ct.signature[0] ^= 1; rejected(&ct);
        let other = scheme.encrypt_cached(&enc, &time, &message, &mut rng);
        assert_ne!(ciphertext.verification_key, other.verification_key);
        let mut ct = ciphertext.clone(); ct.verification_key = other.verification_key; ct.signature = other.signature; rejected(&ct);
    }

    #[test]
    fn recipient_time_setup_and_state_context_are_bound() {
        let mut rng = StdRng::seed_from_u64(0xAF10_CCA2);
        let scheme = Afi06Cca::setup(16, 3, &mut rng);
        let state = scheme.state_at_node(1, &[1, 2], &mut rng);
        let time = scheme.prepare_time(state.current_node());
        let enc = scheme.prepare_encrypt_recipients(&[1, 3]);
        let mut dec = scheme.prepare_receiver_recipients(&[1, 3]);
        scheme.add_receiver_context(&mut dec, 1, &state);
        let ct = scheme.encrypt_cached(&enc, &time, &[7; 32], &mut rng);
        let mut other_set = scheme.prepare_receiver_recipients(&[1, 4]);
        scheme.add_receiver_context(&mut other_set, 1, &state);
        assert!(scheme.decrypt_cached(1, &state, &other_set, &time, &ct).is_none());
        assert!(scheme.decrypt_cached(3, &state, &dec, &time, &ct).is_none());
        let other_time = scheme.prepare_time(&[2, 1]);
        assert!(scheme.decrypt_cached(1, &state, &dec, &other_time, &ct).is_none());
        let other_state = scheme.state_at_node(1, &[2, 1], &mut rng);
        let mut other_dec = scheme.prepare_receiver_recipients(&[1, 3]);
        scheme.add_receiver_context(&mut other_dec, 1, &other_state);
        assert!(scheme.decrypt_cached(1, &other_state, &other_dec, &other_time, &ct).is_none());
        let rerandomized = scheme.state_at_node(1, &[1, 2], &mut rng);
        assert!(scheme.decrypt_cached(1, &rerandomized, &dec, &time, &ct).is_none());
        let other_setup = Afi06Cca::setup(16, 3, &mut rng);
        assert!(other_setup.decrypt_cached(1, &state, &dec, &time, &ct).is_none());
        let outsider = scheme.state_at_node(2, &[1, 2], &mut rng);
        assert!(scheme.decrypt_cached(2, &outsider, &dec, &time, &ct).is_none());
    }

    #[test]
    fn preorder_frontier_advances_without_entering_signature_level() {
        let mut rng = StdRng::seed_from_u64(0xAF10_CCA3);
        let scheme = Afi06Cca::setup(16, 2, &mut rng);
        let expected = [vec![], vec![1], vec![1, 1], vec![1, 2], vec![2], vec![2, 1], vec![2, 2]];
        let enc = scheme.prepare_encrypt_recipients(&[1]);
        let mut state = scheme.initial_state(1, &mut rng);
        for (position, node) in expected.iter().enumerate() {
            assert_eq!(state.current_node(), node);
            let time = scheme.prepare_time(node);
            let mut dec = scheme.prepare_receiver_recipients(&[1]);
            scheme.add_receiver_context(&mut dec, 1, &state);
            let ct = scheme.encrypt_cached(&enc, &time, &[9; 32], &mut rng);
            assert_eq!(scheme.decrypt_cached(1, &state, &dec, &time, &ct), Some([9; 32]));
            assert_eq!(scheme.advance_state(&mut state, &mut rng), position + 1 < expected.len());
            assert!(scheme.decrypt_cached(1, &state, &dec, &time, &ct).is_none());
        }
        assert!(state.is_exhausted());
        assert_eq!(state.number_of_g2_elements(), 0);
        assert!(state.serialized_bytes().is_empty());
        assert!(!scheme.advance_state(&mut state, &mut rng));
    }

    #[test]
    fn direct_target_state_has_the_same_future_nodes_as_sequential_update() {
        let mut rng = StdRng::seed_from_u64(0xAF10_CCA4);
        let scheme = Afi06Cca::setup(16, 3, &mut rng);
        let target = [1, 2, 1];
        let mut sequential = scheme.initial_state(1, &mut rng);
        while sequential.current_node() != target { assert!(scheme.advance_state(&mut sequential, &mut rng)); }
        let mut direct = scheme.state_at_node(1, &target, &mut rng);
        loop {
            assert_eq!(direct.current_node(), sequential.current_node());
            assert_eq!(direct.number_of_g2_elements(), sequential.number_of_g2_elements());
            let direct_more = scheme.advance_state(&mut direct, &mut rng);
            let seq_more = scheme.advance_state(&mut sequential, &mut rng);
            assert_eq!(direct_more, seq_more);
            if !direct_more { break; }
        }
    }
}
