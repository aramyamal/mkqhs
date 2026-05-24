//! Verifiable variance computation on the Efron-Hastie diabetes dataset.
//!
//! The target values y are downloaded at runtime from the original source,
//! distributed across 10 signers, and the evaluator computes
//!
//! $$
//! \operatorname{Var}(y)
//!   = \frac{1}{n}\sum_i y_i^2
//!   - \frac{1}{n^2}\!\left(\sum_i y_i\right)^2
//! $$
//!
//! using `mkqhs_cbr_msq` with rank R=1
//!
//! # Program encoding (R = 1)
//! | coefficient | value   |
//! |-------------|---------|
//! | $a_i$       | $0$     |
//! | $b_i$       | $1/n$   |
//! | $u_i$       | $[1/n]$ |
//! | $v_i$       | $[-1/n]$|
//!
//! $f = \tfrac{1}{n}\sum y_i^2 + \bigl(\tfrac{1}{n}\sum y_i\bigr)\bigl(-\tfrac{1}{n}\sum y_i\bigr)
//!    = \tfrac{1}{n}\sum y_i^2 - \tfrac{1}{n^2}(\sum y_i)^2$

use std::collections::HashMap;

use rand::thread_rng;

use examples::data::load_diabetes;
use mklhs::{
    api::{Scalar, keygen, scalar_inverse, scalar_to_u64, scalar_zero},
    mkqhs_cbr_msq::{eval, sign, verify},
    params::Params,
    types::{Label, QuadProgramMsq, Tag},
};

const K: usize = 8;
const N_SIGNERS: usize = 10;

fn main() {
    let pp = Params::<K>::new();
    let mut rng = thread_rng();

    // data fetch
    let dataset = load_diabetes();
    let y_vals: Vec<u64> = dataset.y.iter().map(|&v| v.round() as u64).collect();
    let n = y_vals.len();
    eprintln!("  n = {n} data points");

    // key generation
    println!("Generating keys for {N_SIGNERS} signers...");
    let mut sks = Vec::with_capacity(N_SIGNERS);
    let mut pks = HashMap::new();
    for _ in 0..N_SIGNERS {
        let (sk, pk) = keygen(&pp, &mut rng).unwrap();
        pks.insert(pk.id(), pk);
        sks.push(sk);
    }

    // signing

    // signer j owns {i : i mod N_SIGNERS == j}.
    println!("Signing {} data points across {N_SIGNERS} signers...", n);
    let mut shares = Vec::with_capacity(n);
    let mut labels = Vec::with_capacity(n);

    for (i, &yi) in y_vals.iter().enumerate() {
        let sk = &sks[i % N_SIGNERS];
        let mut tag_bytes = [0u8; K];
        tag_bytes.copy_from_slice(&(i as u64).to_le_bytes());
        let lab = Label::new(sk.id(), Tag(tag_bytes));
        let share = sign(&pp, sk, lab, Scalar::from(yi)).unwrap();
        shares.push(share);
        labels.push(lab);
    }

    // labeled program construction
    let n_inv = scalar_inverse(&Scalar::from(n as u64)).unwrap();
    let neg_n_inv = -n_inv;
    let zero = scalar_zero();

    let program = QuadProgramMsq::<K, 1>::new(
        vec![zero; n],
        vec![n_inv; n],
        vec![[n_inv]; n],
        vec![[neg_n_inv]; n],
        labels,
    )
    .unwrap();

    // evaluation
    println!("Evaluating...");
    let sig = eval(&pp, &program, shares).unwrap();

    // expected values
    println!("Calculating expected values and comparing...");
    let sum_y_int: u64 = y_vals.iter().sum();
    let sum_y_sq_int: u64 = y_vals.iter().map(|&yi| yi * yi).sum();

    // exact rational numerator fits in u128
    let numerator: u128 = n as u128 * sum_y_sq_int as u128 - sum_y_int as u128 * sum_y_int as u128;
    let denominator: u128 = (n * n) as u128;
    let var_exact = numerator as f64 / denominator as f64;

    // float reference via the mean should agree to floating-point precision
    let mean = sum_y_int as f64 / n as f64;
    let var_float = y_vals
        .iter()
        .map(|&yi| (yi as f64 - mean).powi(2))
        .sum::<f64>()
        / n as f64;

    // field elements for verification
    let sum_y: Scalar = y_vals.iter().map(|&yi| Scalar::from(yi)).sum();
    let sum_y_sq: Scalar = y_vals
        .iter()
        .map(|&yi| Scalar::from(yi) * Scalar::from(yi))
        .sum();
    let expected = n_inv * sum_y_sq - n_inv * n_inv * sum_y * sum_y;

    // Cross-check: expected * n^2 == n * sum(y_i^2) - sum(y_i)^
    let n_scalar = Scalar::from(n as u64);
    let integer_check = expected * n_scalar * n_scalar == n_scalar * sum_y_sq - sum_y * sum_y;
    assert!(
        integer_check,
        "variance field element does not match integer computation"
    );

    // verification
    println!("Verifying...");
    let ok = verify(&pp, &program, &pks, expected, &sig).unwrap();

    println!();
    println!("── Results ─────────────────────────────────────────");
    println!("n = {n}");
    println!("sum(y_i) = {sum_y_int}");
    println!("sum(y_i^2) = {sum_y_sq_int}");
    println!();
    println!("Var(y) = (n*sum(y_i^2) - sum(y_i)^2) / n^2");
    println!("       = ({n} * {sum_y_sq_int} - {sum_y_int}^2) / {n}^2");
    println!("       = {numerator} / {denominator}");
    println!("       = {var_exact:.6}");
    println!();
    println!("── Scalars (BLS12-381 Z_q, decimal) ────────────────");
    println!("sum(y_i)   (Z_q)       = {sum_y}");
    println!("sum(y_i^2) (Z_q)       = {sum_y_sq}");
    println!("n^-1       (Z_q)       = {n_inv}");
    println!("Var(y)     (Z_q)       = {expected}");
    println!();
    // Recover the float from the evaluated scalar: expected = num / n^2, so expected * n^2 = num.
    let den_rec = (n * n) as u64;
    let num_rec = scalar_to_u64(&(expected * n_scalar * n_scalar)).expect("numerator fits in u64");
    let var_from_scalar = num_rec as f64 / den_rec as f64;
    println!("Var(y) from evaluated scalar = scalar_to_u64(Var(y) * n^2) / n^2");
    println!("                             = {num_rec} / {den_rec}");
    println!("                             = {var_from_scalar:.6}");
    println!(
        "Calculated variance in float = {var_float:.6}  (diff: {:.3e})",
        (var_exact - var_float).abs()
    );
    println!(
        "Integer check        : {}",
        if integer_check { "PASS" } else { "FAIL" }
    );
    println!(
        "Scheme verification  : {}",
        if ok { "PASS" } else { "FAIL" }
    );
}
