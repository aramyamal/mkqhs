//! mk-br-qhs1-msq: message-squares variant of mk-br-qhs1.
//!
//! Sign, Eval and Verify as in Figures fig:msq-setup-sign and fig:con1msq of the thesis.
//! `sign` is also re-exported by mk-br-qhs2-msq.

use std::collections::HashMap;

use ark_bls12_381::Bls12_381;
use ark_ec::{CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::Field;
use ark_std::{UniformRand, Zero};

use crate::{
    algebra::{G1, GT, Scalar, g1_gen, g2_gen, hash_to_g1_with, pairing},
    errors::ProtocolError,
    params::Params,
    types::{
        Id, Label, PublicKey, QuadEvalSig1Msq, QuadProgramMsq, SecretKey, SignShareMsq, organize,
    },
};

pub use crate::mk_lhs::keygen;

pub fn sign<const K: usize>(
    pp: &Params<K>,
    sk: &SecretKey<K>,
    label: Label<K>,
    msg: Scalar,
) -> Result<SignShareMsq<K>, ProtocolError> {
    let label_bytes = label.to_bytes();
    let h1 = hash_to_g1_with(pp.h2g1_label(), &label_bytes)?;
    let h2 = hash_to_g1_with(pp.h2g1_label2(), &label_bytes)?;

    let gamma = (h1 + g1_gen() * msg) * (*sk.value());
    let gamma_sq = (h2 + g1_gen() * msg.square()) * (*sk.value());

    Ok(SignShareMsq::new(sk.id(), gamma, gamma_sq, msg))
}

pub fn eval<const K: usize, const R: usize>(
    _pp: &Params<K>,
    program: &QuadProgramMsq<K, R>,
    sign_shares: Vec<SignShareMsq<K>>,
) -> Result<QuadEvalSig1Msq<K, R>, ProtocolError> {
    let n = program.n();
    if sign_shares.len() != n {
        return Err(ProtocolError::InvalidInput(
            "sign_shares/program length mismatch".to_string(),
        ));
    }

    let a = program.a();
    let b = program.b();
    let u = program.u();
    let v = program.v();
    let labels = program.labels();

    let gamma_bases: Vec<_> = sign_shares
        .iter()
        .map(|s| s.gamma().into_affine())
        .collect();
    let gamma_sq_bases: Vec<_> = sign_shares
        .iter()
        .map(|s| s.gamma_sq().into_affine())
        .collect();

    // $\gamma^{(a,b)} = \prod_i \gamma_i^{a_i} (\gamma_i')^{b_i}$
    let gamma_ab = G1::msm_unchecked(&gamma_bases, a) + G1::msm_unchecked(&gamma_sq_bases, b);

    // $\gamma_r^{(u)} = \prod_i \gamma_i^{u_{i,r}}$,
    // $\gamma_r^{(v)} = \prod_i \gamma_i^{v_{i,r}}$
    let gamma_u: [G1; R] = std::array::from_fn(|r| {
        let u_r: Vec<Scalar> = u.iter().map(|ui| ui[r]).collect();
        G1::msm_unchecked(&gamma_bases, &u_r)
    });
    let gamma_v: [G1; R] = std::array::from_fn(|r| {
        let v_r: Vec<Scalar> = v.iter().map(|vi| vi[r]).collect();
        G1::msm_unchecked(&gamma_bases, &v_r)
    });

    let (ord_ids, groups) = organize(labels);
    let t = ord_ids.len();

    // per-id $\mu_{\mathsf{id}}^{(a,b)}$ and
    // $\boldsymbol\mu_{\mathsf{id}}^{(u)}, \boldsymbol\mu_{\mathsf{id}}^{(v)}$
    let mut mu_ab = vec![Scalar::zero(); t];
    let mut mu_u: Vec<[Scalar; R]> = vec![[Scalar::zero(); R]; t];
    let mut mu_v: Vec<[Scalar; R]> = vec![[Scalar::zero(); R]; t];

    for (j, idxs) in groups.iter().enumerate() {
        for &i in idxs {
            let mi = *sign_shares[i].mu();
            mu_ab[j] += a[i] * mi + b[i] * mi.square();
            for r in 0..R {
                mu_u[j][r] += u[i][r] * mi;
                mu_v[j][r] += v[i][r] * mi;
            }
        }
    }

    QuadEvalSig1Msq::new(gamma_ab, gamma_u, gamma_v, mu_ab, mu_u, mu_v)
}

pub fn verify<const K: usize, const R: usize>(
    pp: &Params<K>,
    program: &QuadProgramMsq<K, R>,
    pks: &HashMap<Id<K>, PublicKey<K>>,
    msg: Scalar,
    sig: &QuadEvalSig1Msq<K, R>,
) -> Result<bool, ProtocolError> {
    let (ord_ids, _) = organize(program.labels());
    let t = ord_ids.len();
    let mu_ab = sig.mu_ab();
    let mu_u = sig.mu_u();
    let mu_v = sig.mu_v();

    let mut id_to_j: HashMap<Id<K>, usize> = HashMap::with_capacity(t);
    for (j, &id) in ord_ids.iter().enumerate() {
        id_to_j.insert(id, j);
    }

    // ver1:
    // $$
    // \tilde m = \sum_{\mathsf{id}} \mu_{\mathsf{id}}^{(a,b)} +
    // \langle\sum_{\mathsf{id}} \boldsymbol\mu_{\mathsf{id}}^{(u)},
    // \sum_{\mathsf{id}} \boldsymbol\mu_{\mathsf{id}}^{(v)}\rangle
    // $$
    let mu_ab_sum: Scalar = mu_ab.iter().sum();
    let mut mu_u_sum = [Scalar::zero(); R];
    let mut mu_v_sum = [Scalar::zero(); R];
    for j in 0..t {
        for r in 0..R {
            mu_u_sum[r] += mu_u[j][r];
            mu_v_sum[r] += mu_v[j][r];
        }
    }
    let mu_uv_sum: Scalar = (0..R).map(|r| mu_u_sum[r] * mu_v_sum[r]).sum();
    if mu_ab_sum + mu_uv_sum != msg {
        return Ok(false);
    }

    // Collect pk G2 affine points in ord_ids order
    let g2_pts: Vec<_> = ord_ids
        .iter()
        .map(|id| {
            pks.get(id)
                .ok_or_else(|| ProtocolError::InvalidInput("missing public key".to_string()))
                .map(|pk| pk.value().into_affine())
        })
        .collect::<Result<_, _>>()?;

    // ver2:
    // $$
    // e(\gamma^{(a,b)}, g_2) =
    // \prod_{\mathsf{id}} e(g_1^{\mu_{\mathsf{id}}^{(a,b)}} \cdot
    // \prod_{i\in \mathcal{I}_{\mathsf{id}}} H_1(\ell_i)^{a_i} H_2(\ell_i)^{b_i},
    // \mathsf{pk}_{\mathsf{id}})
    // $$
    let mut a_pts: Vec<G1> = mu_ab.iter().map(|mu_j| g1_gen() * *mu_j).collect();
    {
        let mut h1_bases: Vec<Vec<_>> = vec![Vec::new(); t];
        let mut h1_scalars: Vec<Vec<Scalar>> = vec![Vec::new(); t];
        let mut h2_bases: Vec<Vec<_>> = vec![Vec::new(); t];
        let mut h2_scalars: Vec<Vec<Scalar>> = vec![Vec::new(); t];
        for (i, lab) in program.labels().iter().enumerate() {
            let j = *id_to_j.get(&lab.id()).ok_or_else(|| {
                ProtocolError::InvalidInput("label id not in sig ord_ids".to_string())
            })?;
            let ai = program.a()[i];
            let bi = program.b()[i];
            if !ai.is_zero() {
                let h1 = hash_to_g1_with(pp.h2g1_label(), &lab.to_bytes())?;
                h1_bases[j].push(h1.into_affine());
                h1_scalars[j].push(ai);
            }
            if !bi.is_zero() {
                let h2 = hash_to_g1_with(pp.h2g1_label2(), &lab.to_bytes())?;
                h2_bases[j].push(h2.into_affine());
                h2_scalars[j].push(bi);
            }
        }
        for j in 0..t {
            if !h1_bases[j].is_empty() {
                a_pts[j] += G1::msm_unchecked(&h1_bases[j], &h1_scalars[j]);
            }
            if !h2_bases[j].is_empty() {
                a_pts[j] += G1::msm_unchecked(&h2_bases[j], &h2_scalars[j]);
            }
        }
    }
    let lhs_v2: GT = pairing(sig.gamma_ab(), &g2_gen());
    let rhs_v2: GT = Bls12_381::multi_pairing(
        a_pts.iter().map(|p| p.into_affine()).collect::<Vec<_>>(),
        g2_pts.clone(),
    )
    .0;
    if lhs_v2 != rhs_v2 {
        return Ok(false);
    }

    // ver3:
    // $$
    // e(\Gamma_\rho, g_2) =
    // \prod_{\mathsf{id}} e\!\left(g_1^{\langle\boldsymbol\rho,
    // \boldsymbol\mu_{\mathsf{id}}^{(u)}\rangle + \langle\boldsymbol\rho',
    // \boldsymbol\mu_{\mathsf{id}}^{(v)}\rangle} \cdot
    // \prod_{i\in \mathcal{I}_{\mathsf{id}}} H_1(\ell_i)^{\langle\boldsymbol\rho,
    // \mathbf u_i\rangle+\langle\boldsymbol\rho',\mathbf v_i\rangle},
    // \mathsf{pk}_{\mathsf{id}}\right)
    // $$
    let mut rng = rand::thread_rng();
    let rho: Vec<Scalar> = (0..R).map(|_| Scalar::rand(&mut rng)).collect();
    let rho_prime: Vec<Scalar> = (0..R).map(|_| Scalar::rand(&mut rng)).collect();

    let gu_aff: Vec<_> = sig.gamma_u().iter().map(|p| p.into_affine()).collect();
    let gv_aff: Vec<_> = sig.gamma_v().iter().map(|p| p.into_affine()).collect();
    let gamma_rho = G1::msm_unchecked(&gu_aff, &rho) + G1::msm_unchecked(&gv_aff, &rho_prime);

    let mut b_pts: Vec<G1> = (0..t)
        .map(|j| {
            let s: Scalar = (0..R)
                .map(|r| rho[r] * mu_u[j][r] + rho_prime[r] * mu_v[j][r])
                .sum();
            g1_gen() * s
        })
        .collect();
    {
        let mut hb_bases: Vec<Vec<_>> = vec![Vec::new(); t];
        let mut hb_scalars: Vec<Vec<Scalar>> = vec![Vec::new(); t];
        for (i, lab) in program.labels().iter().enumerate() {
            let j = *id_to_j.get(&lab.id()).unwrap();
            let ui = &program.u()[i];
            let vi = &program.v()[i];
            let coeff: Scalar = (0..R).map(|r| rho[r] * ui[r] + rho_prime[r] * vi[r]).sum();
            if !coeff.is_zero() {
                let h1 = hash_to_g1_with(pp.h2g1_label(), &lab.to_bytes())?;
                hb_bases[j].push(h1.into_affine());
                hb_scalars[j].push(coeff);
            }
        }
        for j in 0..t {
            if !hb_bases[j].is_empty() {
                b_pts[j] += G1::msm_unchecked(&hb_bases[j], &hb_scalars[j]);
            }
        }
    }
    let lhs_v3: GT = pairing(&gamma_rho, &g2_gen());
    let rhs_v3: GT = Bls12_381::multi_pairing(
        b_pts.iter().map(|p| p.into_affine()).collect::<Vec<_>>(),
        g2_pts,
    )
    .0;
    if lhs_v3 != rhs_v3 {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Params;
    use ark_std::{UniformRand, test_rng};
    use rand::RngCore;

    #[test]
    fn sign_smoke() {
        const K: usize = 8;
        let pp = Params::<K>::new();
        let mut rng = test_rng();
        let (sk, _pk) = keygen(&pp, &mut rng).unwrap();
        let mut tag_bytes = [0u8; K];
        rng.try_fill_bytes(&mut tag_bytes).unwrap();
        let label = Label::new(sk.id(), crate::types::Tag(tag_bytes));
        let msg = Scalar::rand(&mut rng);
        let share = sign(&pp, &sk, label, msg).unwrap();
        assert_eq!(share.id(), sk.id());
        assert!(share.gamma() != share.gamma_sq());
    }
}
