use rand::RngCore;
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug)]
pub struct SetupParameters {
    pub max_users: usize,
    pub tree_depth: usize,
}

#[derive(Clone, Debug)]
pub struct KeyPair<PublicKey, SecretKey> {
    pub public: PublicKey,
    pub secret: SecretKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureSupport {
    Yes,
    No,
    NotApplicable,
    ToVerify,
}

impl fmt::Display for FeatureSupport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Yes => "Yes",
            Self::No => "No",
            Self::NotApplicable => "N/A",
            Self::ToVerify => "To verify",
        })
    }
}

#[derive(Clone, Debug)]
pub struct SchemeCapabilities {
    pub distributed_keygen: FeatureSupport,
    pub forward_security: FeatureSupport,
    pub broadcast_encryption: FeatureSupport,
    pub sender_authentication: FeatureSupport,
    pub signcryption: FeatureSupport,
    pub ind_cca: FeatureSupport,
    pub euf_cma: FeatureSupport,
    pub constant_ciphertext: FeatureSupport,
    pub key_update: FeatureSupport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CiphertextStorage {
    pub cryptographic_ciphertext_bytes: usize,
    pub recipient_metadata_bytes: usize,
    pub total_wire_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKeyStorage {
    pub serialized_bytes: usize,
    pub number_of_g1_elements: usize,
    pub number_of_g2_elements: usize,
    pub number_of_zp_elements: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemeError {
    Unsupported {
        scheme: &'static str,
        operation: &'static str,
    },
    InvalidInput(String),
    AuthenticationFailed,
}

impl fmt::Display for SchemeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { scheme, operation } => {
                write!(formatter, "{scheme} does not support {operation}")
            }
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
        }
    }
}

impl Error for SchemeError {}

pub trait SchemeAdapter: Sized {
    type PublicKey: Clone;
    type SecretKey: Clone;
    type Ciphertext: Clone;

    fn scheme_name() -> &'static str;

    fn capabilities() -> SchemeCapabilities;

    fn unsupported(operation: &'static str) -> SchemeError {
        SchemeError::Unsupported {
            scheme: Self::scheme_name(),
            operation,
        }
    }

    fn setup<R: RngCore>(_parameters: SetupParameters, _rng: &mut R) -> Result<Self, SchemeError> {
        Err(Self::unsupported("Setup"))
    }

    fn join<R: RngCore>(
        &self,
        _identity: usize,
        _rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        Err(Self::unsupported("Join"))
    }

    fn keygen<R: RngCore>(
        &self,
        _identity: usize,
        _rng: &mut R,
    ) -> Result<KeyPair<Self::PublicKey, Self::SecretKey>, SchemeError> {
        Err(Self::unsupported("KeyGen"))
    }

    fn update<R: RngCore>(
        &self,
        _secret_key: &Self::SecretKey,
        _child_bit: u8,
        _rng: &mut R,
    ) -> Result<Self::SecretKey, SchemeError> {
        Err(Self::unsupported("Update"))
    }

    fn encrypt<R: RngCore>(
        &self,
        _recipients: &[usize],
        _public_keys: &[Self::PublicKey],
        _message: &[u8; 32],
        _rng: &mut R,
    ) -> Result<Self::Ciphertext, SchemeError> {
        Err(Self::unsupported("Encrypt"))
    }

    fn signcrypt<R: RngCore>(
        &self,
        _sender_secret: &Self::SecretKey,
        _sender_public: &Self::PublicKey,
        _recipients: &[usize],
        _public_keys: &[Self::PublicKey],
        _message: &[u8; 32],
        _rng: &mut R,
    ) -> Result<Self::Ciphertext, SchemeError> {
        Err(Self::unsupported("Signcrypt"))
    }

    fn decrypt(
        &self,
        _receiver: usize,
        _receiver_secret: &Self::SecretKey,
        _recipients: &[usize],
        _public_keys: &[Self::PublicKey],
        _ciphertext: &Self::Ciphertext,
    ) -> Result<[u8; 32], SchemeError> {
        Err(Self::unsupported("Decrypt"))
    }

    fn unsigncrypt(
        &self,
        _receiver: usize,
        _receiver_secret: &Self::SecretKey,
        _sender_public: &Self::PublicKey,
        _recipients: &[usize],
        _public_keys: &[Self::PublicKey],
        _ciphertext: &Self::Ciphertext,
    ) -> Result<[u8; 32], SchemeError> {
        Err(Self::unsupported("Unsigncrypt"))
    }

    fn serialize_ciphertext(
        &self,
        _ciphertext: &Self::Ciphertext,
        _recipients: &[usize],
    ) -> Result<CiphertextStorage, SchemeError> {
        Err(Self::unsupported("SerializeCiphertext"))
    }

    fn serialize_secret_key(
        &self,
        _secret_key: &Self::SecretKey,
    ) -> Result<SecretKeyStorage, SchemeError> {
        Err(Self::unsupported("SerializeSecretKey"))
    }
}
