//! mk-br-qhs2-msq: message-squares variant of mk-br-qhs2.
//!
//! Eval and Verify as in Figure fig:con2msq of the thesis.
//! Sign is shared with mk-br-qhs1-msq; use `mk_br_qhs1_msq::sign_msq`.
//!
//! Compared to qhs1-msq, per-id quadratic components are compressed using
//! a Fiat-Shamir hash H_FS, reducing evaluated signature size from O(tR) to O(t + R).

use std::collections::HashMap;

use ark_bls12_381::Bls12_381;
use ark_ec::{CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use sha2::{Digest, Sha256};

pub use crate::mk_br_qhs1_msq::sign;
pub use crate::mk_lhs::keygen;

use crate::{
    algebra::{G1, GT, Scalar, g1_gen, g2_gen, hash_to_g1_with, pairing},
    errors::ProtocolError,
    params::Params,
    types::{Id, PublicKey, QuadEvalSig2Msq, QuadProgramMsq, SignShareMsq, organize},
};

/// Fiat-Shamir hash H_FS.  Serialises all public inputs to bytes and derives
/// 2R scalars via SHA-256.
fn h_fs<const K: usize, const R: usize>(
    program: &QuadProgramMsq<K, R>,
    gamma_ab: &G1,
    gamma_u: &[G1],
    gamma_v: &[G1],
    mu_ab: &[Scalar],
    mu_u_global: &[Scalar; R],
    mu_v_global: &[Scalar; R],
) -> ([Scalar; R], [Scalar; R]) {
    let mut buf = Vec::new();

    // Program labels and coefficients
    for lab in program.labels() {
        buf.extend_from_slice(&lab.to_bytes());
    }
    for x in program.a() {
        x.serialize_compressed(&mut buf).unwrap();
    }
    for x in program.b() {
        x.serialize_compressed(&mut buf).unwrap();
    }
    for ui in program.u() {
        for x in ui {
            x.serialize_compressed(&mut buf).unwrap();
        }
    }
    for vi in program.v() {
        for x in vi {
            x.serialize_compressed(&mut buf).unwrap();
        }
    }

    // Gamma components
    gamma_ab.serialize_compressed(&mut buf).unwrap();
    for g in gamma_u {
        g.serialize_compressed(&mut buf).unwrap();
    }
    for g in gamma_v {
        g.serialize_compressed(&mut buf).unwrap();
    }

    // Per-id linear-square sums and global quadratic vectors
    for x in mu_ab {
        x.serialize_compressed(&mut buf).unwrap();
    }
    for x in mu_u_global {
        x.serialize_compressed(&mut buf).unwrap();
    }
    for x in mu_v_global {
        x.serialize_compressed(&mut buf).unwrap();
    }

    let seed: [u8; 32] = Sha256::digest(&buf).into();

    let derive = |idx: u64| {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(idx.to_le_bytes());
        let bytes: [u8; 32] = h.finalize().into();
        Scalar::from_le_bytes_mod_order(&bytes)
    };

    let mut rho = [Scalar::zero(); R];
    let mut rho_prime = [Scalar::zero(); R];
    for r in 0..R {
        rho[r] = derive(r as u64);
        rho_prime[r] = derive(R as u64 + r as u64);
    }
    (rho, rho_prime)
}

pub fn eval<const K: usize, const R: usize>(
    _pp: &Params<K>,
    program: &QuadProgramMsq<K, R>,
    sign_shares: Vec<SignShareMsq<K>>,
) -> Result<QuadEvalSig2Msq<K, R>, ProtocolError> {
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

    // $\gamma_r^{(u)} = \prod_i \gamma_i^{u_{i,r}}$, $\gamma_r^{(v)} = \prod_i \gamma_i^{v_{i,r}}$
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
    // $\boldsymbol\mu_{\mathsf{id}}^{(u)}, \boldsymbol\mu_{\mathsf{id}}^{(v)}$;
    // also global $\boldsymbol\mu^{(u)}, \boldsymbol\mu^{(v)}$
    let mut mu_ab = vec![Scalar::zero(); t];
    let mut mu_u_per_id: Vec<[Scalar; R]> = vec![[Scalar::zero(); R]; t];
    let mut mu_v_per_id: Vec<[Scalar; R]> = vec![[Scalar::zero(); R]; t];
    let mut mu_u_global = [Scalar::zero(); R];
    let mut mu_v_global = [Scalar::zero(); R];

    for (j, idxs) in groups.iter().enumerate() {
        for &i in idxs {
            let mi = *sign_shares[i].mu();
            mu_ab[j] += a[i] * mi + b[i] * mi.square();
            for r in 0..R {
                let mu_ui = u[i][r] * mi;
                let mu_vi = v[i][r] * mi;
                mu_u_per_id[j][r] += mu_ui;
                mu_v_per_id[j][r] += mu_vi;
                mu_u_global[r] += mu_ui;
                mu_v_global[r] += mu_vi;
            }
        }
    }

    // derive Fiat-Shamir challenge
    // $$
    // (\boldsymbol\rho, \boldsymbol\rho') \gets
    // H_\mathsf{FS}(\mathcal{P}, \tilde\gamma, \{\mu_{\mathsf{id}}^{(a,b)}\}, \boldsymbol\mu^{(u)},
    // \boldsymbol\mu^{(v)})
    // $$
    let (rho, rho_prime) = h_fs(
        program,
        &gamma_ab,
        &gamma_u,
        &gamma_v,
        &mu_ab,
        &mu_u_global,
        &mu_v_global,
    );

    // $$
    // \tilde\mu_{\mathsf{id}}^{(u,v)} = \langle\boldsymbol\rho,
    // \boldsymbol\mu_{\mathsf{id}}^{(u)}\rangle +
    // \langle\boldsymbol\rho', \boldsymbol\mu_{\mathsf{id}}^{(v)}\rangle
    // $$
    let mu_uv: Vec<Scalar> = (0..t)
        .map(|j| {
            (0..R)
                .map(|r| rho[r] * mu_u_per_id[j][r] + rho_prime[r] * mu_v_per_id[j][r])
                .sum()
        })
        .collect();

    QuadEvalSig2Msq::new(
        gamma_ab,
        gamma_u,
        gamma_v,
        mu_ab,
        mu_uv,
        mu_u_global,
        mu_v_global,
    )
}

pub fn verify<const K: usize, const R: usize>(
    pp: &Params<K>,
    program: &QuadProgramMsq<K, R>,
    pks: &HashMap<Id<K>, PublicKey<K>>,
    msg: Scalar,
    sig: &QuadEvalSig2Msq<K, R>,
) -> Result<bool, ProtocolError> {
    let (ord_ids, _) = organize(program.labels());
    let t = ord_ids.len();
    let mu_ab = sig.mu_ab();
    let mu_uv = sig.mu_uv();
    let mu_u_global = sig.mu_u_global();
    let mu_v_global = sig.mu_v_global();

    let mut id_to_j: HashMap<Id<K>, usize> = HashMap::with_capacity(t);
    for (j, &id) in ord_ids.iter().enumerate() {
        id_to_j.insert(id, j);
    }

    // Recompute Fiat-Shamir challenge
    let (rho, rho_prime) = h_fs(
        program,
        sig.gamma_ab(),
        sig.gamma_u(),
        sig.gamma_v(),
        mu_ab,
        mu_u_global,
        mu_v_global,
    );

    // ver1:
    // $$
    // \tilde m = \sum_{\mathsf{id}} \mu_{\mathsf{id}}^{(a,b)} +
    // \langle\boldsymbol\mu^{(u)}, \boldsymbol\mu^{(v)}\rangle
    // $$
    let mu_ab_sum: Scalar = mu_ab.iter().sum();
    let mu_uv_sum: Scalar = (0..R).map(|r| mu_u_global[r] * mu_v_global[r]).sum();
    if mu_ab_sum + mu_uv_sum != msg {
        return Ok(false);
    }

    // Collect pk G2 affine points
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
    // e(\gamma^{(a,b)}, g_2) = \prod_{\mathsf{id}} e\!\left(g_1^{\mu_{\mathsf{id}}^{(a,b)}} \cdot
    // \prod_{i\in \mathcal{I}_{\mathsf{id}}}
    // H_1(\ell_i)^{a_i} H_2(\ell_i)^{b_i},\ \mathsf{pk}_{\mathsf{id}}\right)
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
    // \sum_{\mathsf{id}} \tilde\mu_{\mathsf{id}}^{(u,v)} =
    // \langle\boldsymbol\rho, \boldsymbol\mu^{(u)}\rangle +
    // \langle\boldsymbol\rho', \boldsymbol\mu^{(v)}\rangle
    // $$
    let mu_uv_sum: Scalar = mu_uv.iter().sum();
    let rho_dot_u: Scalar = (0..R).map(|r| rho[r] * mu_u_global[r]).sum();
    let rhop_dot_v: Scalar = (0..R).map(|r| rho_prime[r] * mu_v_global[r]).sum();
    if mu_uv_sum != rho_dot_u + rhop_dot_v {
        return Ok(false);
    }

    // ver4:
    // $$
    // e(\Gamma_\rho, g_2) = \prod_{\mathsf{id}} e\!\left(g_1^{\tilde\mu_{\mathsf{id}}^{(u,v)}}
    // \cdot \prod_{i\in \mathcal{I}_{\mathsf{id}}} H_1(\ell_i)^{\langle\boldsymbol\rho,
    // \mathbf u_i\rangle+\langle\boldsymbol\rho',\mathbf v_i\rangle},
    // \mathsf{pk}_{\mathsf{id}}\right)
    // $$
    let gu_aff: Vec<_> = sig.gamma_u().iter().map(|p| p.into_affine()).collect();
    let gv_aff: Vec<_> = sig.gamma_v().iter().map(|p| p.into_affine()).collect();
    let gamma_rho = G1::msm_unchecked(&gu_aff, &rho) + G1::msm_unchecked(&gv_aff, &rho_prime);

    let mut c_pts: Vec<G1> = mu_uv.iter().map(|s| g1_gen() * *s).collect();
    {
        let mut hc_bases: Vec<Vec<_>> = vec![Vec::new(); t];
        let mut hc_scalars: Vec<Vec<Scalar>> = vec![Vec::new(); t];
        for (i, lab) in program.labels().iter().enumerate() {
            let j = *id_to_j.get(&lab.id()).unwrap();
            let ui = &program.u()[i];
            let vi = &program.v()[i];
            let coeff: Scalar = (0..R).map(|r| rho[r] * ui[r] + rho_prime[r] * vi[r]).sum();
            if !coeff.is_zero() {
                let h1 = hash_to_g1_with(pp.h2g1_label(), &lab.to_bytes())?;
                hc_bases[j].push(h1.into_affine());
                hc_scalars[j].push(coeff);
            }
        }
        for j in 0..t {
            if !hc_bases[j].is_empty() {
                c_pts[j] += G1::msm_unchecked(&hc_bases[j], &hc_scalars[j]);
            }
        }
    }
    let lhs_v4: GT = pairing(&gamma_rho, &g2_gen());
    let rhs_v4: GT = Bls12_381::multi_pairing(
        c_pts.iter().map(|p| p.into_affine()).collect::<Vec<_>>(),
        g2_pts,
    )
    .0;
    if lhs_v4 != rhs_v4 {
        return Ok(false);
    }

    Ok(true)
}
