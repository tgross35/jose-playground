use std::{convert::Infallible, fmt::Debug};

use serde::{Deserialize, Serialize};

use hmac::{Hmac, Mac, digest::InvalidLength};
use sha2::Sha256;

#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    /// EdDSA signature algorithms (Optional)
    #[serde(rename = "EdDSA")]
    EdDsa,

    /// ECDSA using P-256 and SHA-256 (Recommended+)
    Es256,

    /// ECDSA using secp256k1 curve and SHA-256 (Optional)
    Es256K,

    /// ECDSA using P-384 and SHA-384 (Optional)
    Es384,

    /// ECDSA using P-521 and SHA-512 (Optional)
    Es512,

    /// HMAC using SHA-256 (Required)
    Hs256,

    /// HMAC using SHA-384 (Optional)
    Hs384,

    /// HMAC using SHA-512 (Optional)
    Hs512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
    Ps256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
    Ps384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
    Ps512,

    /// RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
    Rs256,

    /// RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
    Rs384,

    /// RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
    Rs512,

    /// No digital signature or MAC performed (Optional)
    ///
    /// This variant is renamed as `Null` to avoid colliding with `Option::None`.
    #[serde(rename = "none")]
    Null,
}

/// Trait for both signed and unsigned data
pub trait MaybeSigned {
    /// Data representing signature type
    type SigData;
}

/// Trait for all serializable algorithms
pub trait SigningAlg: MaybeSigned + Sized {
    const ALGORITHM: Algorithm;
    type Error: Debug;

    fn mac_new_from_slice(key: &[u8]) -> Result<Self, Self::Error>;
    fn mac_update(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn mac_finalize(self) -> Result<Self::SigData, Self::Error>;
}

/// Not yet signed. Note: does not implement serialized
pub struct Unsigned {}

/// Signing algorithm is unknown for e.g., incoming JWEs where type may not be
/// known in advance
pub struct AnySigning {}

impl MaybeSigned for Unsigned {
    type SigData = ();
}

type HmacSha256 = Hmac<Sha256>;

impl MaybeSigned for HmacSha256 {
    type SigData =  Vec<u8>;
}

impl SigningAlg for HmacSha256 {
    const ALGORITHM: Algorithm = Algorithm::Hs256;

    type Error = Infallible;

    fn mac_new_from_slice(key: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::new_from_slice(key).unwrap())
    }
    
    fn mac_update(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.update(data);
        Ok(())
    }

    fn mac_finalize(self) -> Result<Self::SigData, Self::Error> {
        Ok(self.finalize().into_bytes().to_vec())
    }
}
