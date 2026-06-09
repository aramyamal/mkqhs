//! mkqhs-cbr: compressed bounded-rank quadratic homomorphic signature scheme.
//!
//! Eval and Verify as in Figure 6.1 of the thesis.
//! Reduces evaluated signature size from O(tR) to O(t + R) by compressing per-identity
//! quadratic components.
//!
//! Setup, KeyGen, and Sign are from mklhs (Figure 5.1) (see `mklhs::keygen` and `mklhs::sign`).

pub use crate::mklhs::keygen;

use std::collections::HashMap;

use crate::{
    algebra::Scalar,
    errors::ProtocolError,
    params::Params,
    types::{Id, PublicKey, QuadEvalSig2, QuadProgram, SignShare},
};

pub fn eval<const K: usize, const R: usize>(
    _pp: &Params<K>,
    _program: &QuadProgram<K, R>,
    _sign_shares: Vec<SignShare<K>>,
) -> Result<QuadEvalSig2<K, R>, ProtocolError> {
    todo!(
        "mkqhs_cbr eval: same gamma as qhs1, then H_FS compression of per-id quadratic components"
    )
}

pub fn verify<const K: usize, const R: usize>(
    _pp: &Params<K>,
    _program: &QuadProgram<K, R>,
    _pks: &HashMap<Id<K>, PublicKey<K>>,
    _msg: Scalar,
    _sig: &QuadEvalSig2<K, R>,
) -> Result<bool, ProtocolError> {
    todo!("mkqhs_cbr verify: ver1-ver4, recompute H_FS, four checks")
}
