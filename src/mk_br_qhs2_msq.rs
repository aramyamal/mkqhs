//! mk-br-qhs2-msq: message-squares variant of mk-br-qhs2.
//!
//! Eval and Verify as in Figure fig:con2msq of the thesis.
//! Sign is shared with mk-br-qhs1-msq; use `mk_br_qhs1_msq::sign_msq`.

use std::collections::HashMap;

use crate::{
    algebra::Scalar,
    errors::ProtocolError,
    params::Params,
    types::{Id, PublicKey, QuadEvalSig2Msq, QuadProgramMsq, SignShareMsq},
};

pub fn eval<const K: usize, const R: usize>(
    _pp: &Params<K>,
    _program: &QuadProgramMsq<K, R>,
    _sign_shares: Vec<SignShareMsq<K>>,
) -> Result<QuadEvalSig2Msq<K, R>, ProtocolError> {
    todo!("mk-br-qhs2-msq eval: same as qhs2 eval but replace gamma_a/mu_a with gamma_ab/mu_ab")
}

pub fn verify<const K: usize, const R: usize>(
    _pp: &Params<K>,
    _program: &QuadProgramMsq<K, R>,
    _pks: &HashMap<Id<K>, PublicKey<K>>,
    _msg: Scalar,
    _sig: &QuadEvalSig2Msq<K, R>,
) -> Result<bool, ProtocolError> {
    todo!("mk-br-qhs2-msq verify: same as qhs2 but ver2 uses H1^a_i * H2^b_i per label")
}
