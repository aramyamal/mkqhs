//! Test helpers for msq scheme variants.
//!
//! Provides the `MsqScheme` trait and tag types `Qhs1Msq`/`Qhs2Msq` so that
//! `tests/msq.rs` can run the same test suite against both variants generically.
//! Not part of the public API.

use std::collections::HashMap;

use crate::{
    algebra::Scalar,
    errors::ProtocolError,
    params::Params,
    types::{Id, PublicKey, QuadEvalSig1Msq, QuadEvalSig2Msq, QuadProgramMsq, SignShareMsq},
};

#[doc(hidden)]
pub trait MsqScheme<const K: usize, const R: usize> {
    type Sig;

    fn eval(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        shares: Vec<SignShareMsq<K>>,
    ) -> Result<Self::Sig, ProtocolError>;

    fn verify(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        pks: &HashMap<Id<K>, PublicKey<K>>,
        msg: Scalar,
        sig: &Self::Sig,
    ) -> Result<bool, ProtocolError>;
}

#[doc(hidden)]
pub struct Qhs1Msq;
#[doc(hidden)]
pub struct Qhs2Msq;

impl<const K: usize, const R: usize> MsqScheme<K, R> for Qhs1Msq {
    type Sig = QuadEvalSig1Msq<K, R>;

    fn eval(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        shares: Vec<SignShareMsq<K>>,
    ) -> Result<Self::Sig, ProtocolError> {
        crate::mk_brq_hs1_msq::eval(pp, program, shares)
    }

    fn verify(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        pks: &HashMap<Id<K>, PublicKey<K>>,
        msg: Scalar,
        sig: &Self::Sig,
    ) -> Result<bool, ProtocolError> {
        crate::mk_brq_hs1_msq::verify(pp, program, pks, msg, sig)
    }
}

impl<const K: usize, const R: usize> MsqScheme<K, R> for Qhs2Msq {
    type Sig = QuadEvalSig2Msq<K, R>;

    fn eval(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        shares: Vec<SignShareMsq<K>>,
    ) -> Result<Self::Sig, ProtocolError> {
        crate::mk_brq_hs2_msq::eval(pp, program, shares)
    }

    fn verify(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        pks: &HashMap<Id<K>, PublicKey<K>>,
        msg: Scalar,
        sig: &Self::Sig,
    ) -> Result<bool, ProtocolError> {
        crate::mk_brq_hs2_msq::verify(pp, program, pks, msg, sig)
    }
}
