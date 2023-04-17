use std::marker::PhantomData;
use types::*;

use crate::sign_alg::{MaybeSigned, SigningAlg, Unsigned};
mod types;

pub enum AnyJws<T, Phd, Uhd, Sign: MaybeSigned> {
    Compact(Jws<T, Compact<Phd, Sign>>),
    General(Jws<T, General<Phd, Uhd, Sign>>),
    Flat(Jws<T, Flat<Phd, Uhd, Sign>>),
}

impl<T, Phd, Uhd, Sign: MaybeSigned> AnyJws<T, Phd, Uhd, Sign> {
    pub fn payload(&self) -> &T {
        match &self {
            AnyJws::Compact(v) => v.payload(),
            AnyJws::General(v) => v.payload(),
            AnyJws::Flat(v) => v.payload(),
        }
    }
}

pub struct Jws<T, Fmt: JwsFormat = Compact<Empty, Unsigned>> {
    payload: T,
    data: Fmt,
}

impl<T, Fmt: JwsFormat> Jws<T, Fmt> {
    pub fn payload(&self) -> &T {
        &self.payload
    }
}

impl<T, Phd, Sign: MaybeSigned> Jws<T, Compact<Phd, Sign>> {
    /// Generate the signature
    pub fn signature<Alg: SigningAlg>(&self, key: impl AsRef<[u8]>) -> Result<Alg::SigData, Alg::Error> {
        let mut mac = Alg::mac_new_from_slice(key.as_ref()).unwrap();
        mac.mac_update(b"data").unwrap();
        mac.mac_finalize()
    }

    /// Return a type that is signed with the given algorithm
    pub fn sign_with<Alg: SigningAlg>(&mut self, key: impl AsRef<[u8]>) -> Result<Compact<Phd, Alg>, Alg::Error> {
        todo!()
    }
}

impl<T, Phd, Uhd, Sign: MaybeSigned> Jws<T, Flat<Phd, Uhd, Sign>> {
    /// Generate the signature
    pub fn signature<Alg: SigningAlg>(&self, key: impl AsRef<[u8]>) -> Result<Alg::SigData, Alg::Error> {
        todo!()
    }

    /// Return a type that is signed with the given algorithm
    pub fn sign_with<Alg: SigningAlg>(&mut self, key: impl AsRef<[u8]>) -> Result<Flat<Phd, Uhd, Alg>, Alg::Error> {
        todo!()
    }
}
