//! mk-br-qhs1-msq: message-squares variant of mk-br-qhs1.
//!
//! Sign, Eval and Verify as in Figures fig:msq-setup-sign and fig:con1msq of the thesis.
//! The `sign_msq` function here is also used by mk-br-qhs2-msq.

use std::collections::HashMap;

use crate::{
    algebra::Scalar,
    errors::ProtocolError,
    params::Params,
    types::{Id, Label, PublicKey, QuadEvalSig1Msq, QuadProgramMsq, SecretKey, SignShareMsq},
};

/// Sign for the message-squares variants (Figure fig:msq-setup-sign).
pub fn sign_msq<const K: usize>(
    _pp: &Params<K>,
    _sk: &SecretKey<K>,
    _label: Label<K>,
    _msg: Scalar,
) -> Result<SignShareMsq<K>, ProtocolError> {
    todo!("sign_msq: hash label with H1 and H2, compute gamma and gamma_sq under sk")
}

pub fn eval<const K: usize, const R: usize>(
    _pp: &Params<K>,
    _program: &QuadProgramMsq<K, R>,
    _sign_shares: Vec<SignShareMsq<K>>,
) -> Result<QuadEvalSig1Msq<K, R>, ProtocolError> {
    todo!("mk-br-qhs1-msq eval: absorb b_i*mu_i^2 into gamma_ab and mu_ab, rest identical to qhs1")
}

pub fn verify<const K: usize, const R: usize>(
    _pp: &Params<K>,
    _program: &QuadProgramMsq<K, R>,
    _pks: &HashMap<Id<K>, PublicKey<K>>,
    _msg: Scalar,
    _sig: &QuadEvalSig1Msq<K, R>,
) -> Result<bool, ProtocolError> {
    todo!("mk-br-qhs1-msq verify: same as qhs1 but ver2 uses H1^a_i * H2^b_i per label")
}
