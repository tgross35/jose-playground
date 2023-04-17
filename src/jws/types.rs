use serde::Serialize;

use crate::sign_alg::{MaybeSigned, Unsigned, Algorithm};

/// Represents JWS forma: compact, general, or flat
pub trait JwsFormat {
    // type Signed;
    // type Unsigned;
}

/// Compact format, allows only protected header data
pub struct Compact<Phd, Signed: MaybeSigned> {
    signature: Signature<Phd, Empty, Signed>,
}

/// Flat format, allows protected and unprotected header data
pub struct Flat<Phd, Uhd, Signed: MaybeSigned> {
    signature: Signature<Phd, Uhd, Signed>,
}

/// General format, allows >1 signature
pub struct General<Phd, Uhd, Signed: MaybeSigned> {
    signatures: Vec<Signature<Phd, Uhd, Signed>>,
}

impl<Phd, Signed: MaybeSigned> JwsFormat for Compact<Phd, Signed> {
    // type Signed = Compact<Phd, Signed>;
    // type Unsigned = Compact<Phd, Unsigned>;
}

impl<Phd, Uhd, Signed: MaybeSigned> JwsFormat for Flat<Phd, Uhd, Signed> {
    // type Signed = Flat<Phd, Uhd, Signed>;
    // type Unsigned = Flat<Phd, Uhd, Unsigned>;
}

impl<Phd, Uhd, Signed: MaybeSigned> JwsFormat for General<Phd, Uhd, Signed> {
    // type Signed = General<Phd, Uhd, Signed>;
    // type Unsigned = General<Phd, Uhd, Unsigned>;
}

/// No data
pub struct Empty {}

/// Header + signature
pub struct Signature<Phd, Uhd, Alg: MaybeSigned> {
    protected: Protected<Phd>,
    unprotected: Unprotected<Uhd>,
    signature: Alg::SigData,
}

/// Protected header data
#[derive(Clone, Debug, Serialize)]
pub struct Protected<Phd> {
    alg: Option<Algorithm>,
    #[serde(flatten)]
    extra: Phd,
}

impl <Phd: Serialize> Protected<Phd> {

}

/// Unprotected header data
#[derive(Clone, Debug, Serialize)]
pub struct Unprotected<Uhd> {
    #[serde(flatten)]
    extra: Uhd,
}
