//! Print artifact sizes in bytes for mklhs and mkqhs-cbr-msq.
//!
//! Run:  cargo bench --bench artifact_sizes

use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, test_rng};

use mkqhs::{
    api::Scalar,
    mklhs::{eval as lhs_eval, sign as lhs_sign},
    mkqhs_cbr_msq::{eval as msq_eval, keygen, sign as msq_sign},
    params::Params,
    types::{
        Label, LabeledProgram, PublicKey, QuadEvalSig2Msq, QuadProgramMsq, SecretKey, SignAggr,
        SignShare, SignShareMsq, Tag,
    },
};

const K: usize = 8;
const T_VALUES: &[usize] = &[2, 5, 10];

fn sk_size(sk: &SecretKey<K>) -> usize {
    sk.value().compressed_size()
}

fn pk_size(pk: &PublicKey<K>) -> usize {
    pk.value().into_affine().compressed_size()
}

fn lhs_fresh_sig_size(s: &SignShare<K>) -> usize {
    s.gamma().into_affine().compressed_size() + s.mu().compressed_size()
}

fn lhs_eval_sig_size(sig: &SignAggr<K>) -> usize {
    sig.gamma().into_affine().compressed_size()
        + sig.mus().iter().map(|s| s.compressed_size()).sum::<usize>()
}

fn make_lhs_eval_sig(pp: &Params<K>, t: usize) -> SignAggr<K> {
    let mut rng = test_rng();
    let mut sks = Vec::new();
    for _ in 0..t {
        let (sk, _pk) = keygen(pp, &mut rng).unwrap();
        sks.push(sk);
    }
    let msgs: Vec<Scalar> = (0..t).map(|_| Scalar::rand(&mut rng)).collect();
    let mut labels = Vec::new();
    let mut shares = Vec::new();
    for i in 0..t {
        let lab = Label::new(sks[i].id(), Tag((i as u64).to_le_bytes()));
        labels.push(lab);
        shares.push(lhs_sign(pp, &sks[i], lab, msgs[i]).unwrap());
    }
    let coeffs: Vec<Scalar> = (0..t).map(|_| Scalar::rand(&mut rng)).collect();
    let program = LabeledProgram::new(coeffs, labels).unwrap();
    lhs_eval(pp, &program, shares).unwrap()
}

fn msq_fresh_sig_size(s: &SignShareMsq<K>) -> usize {
    s.gamma().into_affine().compressed_size()
        + s.gamma_sq().into_affine().compressed_size()
        + s.mu().compressed_size()
}

fn msq_eval_sig_size<const R: usize>(sig: &QuadEvalSig2Msq<K, R>) -> usize {
    let mut n = sig.gamma_ab().into_affine().compressed_size();
    for g in sig.gamma_u() {
        n += g.into_affine().compressed_size();
    }
    for g in sig.gamma_v() {
        n += g.into_affine().compressed_size();
    }
    for s in sig.mu_ab() {
        n += s.compressed_size();
    }
    for s in sig.mu_uv() {
        n += s.compressed_size();
    }
    for s in sig.mu_u_global() {
        n += s.compressed_size();
    }
    for s in sig.mu_v_global() {
        n += s.compressed_size();
    }
    n
}

fn make_msq_eval_sig<const R: usize>(pp: &Params<K>, t: usize) -> QuadEvalSig2Msq<K, R> {
    let mut rng = test_rng();
    let mut sks = Vec::new();
    for _ in 0..t {
        let (sk, _pk) = keygen(pp, &mut rng).unwrap();
        sks.push(sk);
    }
    let msgs: Vec<Scalar> = (0..t).map(|_| Scalar::rand(&mut rng)).collect();
    let mut labels = Vec::new();
    let mut shares = Vec::new();
    for i in 0..t {
        let lab = Label::new(sks[i].id(), Tag((i as u64).to_le_bytes()));
        labels.push(lab);
        shares.push(msq_sign(pp, &sks[i], lab, msgs[i]).unwrap());
    }
    let a_coeffs: Vec<Scalar> = (0..t).map(|_| Scalar::rand(&mut rng)).collect();
    let b_coeffs: Vec<Scalar> = (0..t).map(|_| Scalar::rand(&mut rng)).collect();
    let u_mat: Vec<[Scalar; R]> = (0..t)
        .map(|_| std::array::from_fn(|_| Scalar::rand(&mut rng)))
        .collect();
    let v_mat: Vec<[Scalar; R]> = (0..t)
        .map(|_| std::array::from_fn(|_| Scalar::rand(&mut rng)))
        .collect();
    let program = QuadProgramMsq::<K, R>::new(a_coeffs, b_coeffs, u_mat, v_mat, labels).unwrap();
    msq_eval(pp, &program, shares).unwrap()
}

fn main() {
    let pp = Params::<K>::new();
    let mut rng = test_rng();

    let (sk, pk) = keygen(&pp, &mut rng).unwrap();
    let msg = Scalar::rand(&mut rng);
    let lab = Label::new(sk.id(), Tag([0u8; K]));

    println!("=== mklhs artifact sizes ===");
    println!("  SecretKey:              {:4} B", sk_size(&sk));
    println!("  PublicKey:              {:4} B", pk_size(&pk));
    let share = lhs_sign(&pp, &sk, lab, msg).unwrap();
    println!(
        "  FreshSig:               {:4} B",
        lhs_fresh_sig_size(&share)
    );
    for &t in T_VALUES {
        let sig = make_lhs_eval_sig(&pp, t);
        println!(
            "  EvalSig (t={t:2}):         {:4} B",
            lhs_eval_sig_size(&sig)
        );
    }

    println!();
    println!("=== mkqhs_cbr_msq artifact sizes ===");
    println!("  SecretKey:              {:4} B", sk_size(&sk));
    println!("  PublicKey:              {:4} B", pk_size(&pk));
    let share = msq_sign(&pp, &sk, lab, msg).unwrap();
    println!(
        "  FreshSig:               {:4} B",
        msq_fresh_sig_size(&share)
    );
    for &t in T_VALUES {
        macro_rules! msq_line {
            ($r:literal) => {{
                let sig = make_msq_eval_sig::<$r>(&pp, t);
                println!(
                    "  EvalSig (R={:2}, t={t:2}):   {:4} B",
                    $r,
                    msq_eval_sig_size(&sig)
                );
            }};
        }
        msq_line!(1);
        msq_line!(2);
        msq_line!(4);
        msq_line!(8);
        msq_line!(16);
    }
}
