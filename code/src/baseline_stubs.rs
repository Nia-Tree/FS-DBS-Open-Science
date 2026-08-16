//! Phase-gated baseline adapters.
//!
//! These adapters intentionally return `Unsupported` until their cited paper
//! formulas and implementation mappings have passed the phase-specific audit.
//! No timing sample is emitted for a stub.

use crate::scheme_adapter::{FeatureSupport, SchemeAdapter, SchemeCapabilities};

macro_rules! pending_adapter {
    ($type_name:ident, $scheme_name:literal) => {
        pub struct $type_name;

        impl SchemeAdapter for $type_name {
            type PublicKey = ();
            type SecretKey = ();
            type Ciphertext = ();

            fn scheme_name() -> &'static str {
                $scheme_name
            }

            fn capabilities() -> SchemeCapabilities {
                SchemeCapabilities {
                    distributed_keygen: FeatureSupport::ToVerify,
                    forward_security: FeatureSupport::ToVerify,
                    broadcast_encryption: FeatureSupport::ToVerify,
                    sender_authentication: FeatureSupport::ToVerify,
                    signcryption: FeatureSupport::ToVerify,
                    ind_cca: FeatureSupport::ToVerify,
                    euf_cma: FeatureSupport::ToVerify,
                    constant_ciphertext: FeatureSupport::ToVerify,
                    key_update: FeatureSupport::ToVerify,
                }
            }
        }
    };
}

pending_adapter!(Selvi09Pending, "Selvi09");
pending_adapter!(Gao25Pending, "Gao25");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme_adapter::{SchemeError, SetupParameters};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn pending_baseline_never_produces_a_fake_measurement() {
        let mut rng = StdRng::seed_from_u64(1);
        let result = Selvi09Pending::setup(
            SetupParameters {
                max_users: 16,
                tree_depth: 4,
            },
            &mut rng,
        );
        assert!(matches!(result, Err(SchemeError::Unsupported { .. })));
    }
}
