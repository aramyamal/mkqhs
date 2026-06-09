//! mkqhs-br: baseline bounded-rank quadratic homomorphic signature scheme.
//!
//! Eval and Verify as in Figure 5.2 of the thesis.
//! Setup, KeyGen, and Sign are from mklhs as in Figure 5.1 of the thesis.

pub use crate::mklhs::keygen;

use std::collections::HashMap;

use crate::{
    algebra::Scalar,
    errors::ProtocolError,
    params::Params,
    types::{Id, PublicKey, QuadEvalSig1, QuadProgram, SignShare},
};

pub fn eval<const K: usize, const R: usize>(
    _pp: &Params<K>,
    _program: &QuadProgram<K, R>,
    _sign_shares: Vec<SignShare<K>>,
) -> Result<QuadEvalSig1<K, R>, ProtocolError> {
    todo!("mkqhs_br eval: MSM for gamma components, per-id mu aggregation")
}

pub fn verify<const K: usize, const R: usize>(
    _pp: &Params<K>,
    _program: &QuadProgram<K, R>,
    _pks: &HashMap<Id<K>, PublicKey<K>>,
    _msg: Scalar,
    _sig: &QuadEvalSig1<K, R>,
) -> Result<bool, ProtocolError> {
    todo!("mkqhs_br verify: ver1 scalar check, ver2 linear pairing, ver3 random-coins pairing")
}
