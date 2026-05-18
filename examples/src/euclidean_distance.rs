//! Verifiable squared Euclidean distance on diabetes patient features.
//!
//! Two patients 3-dimensional data points (age, bmi, bp) are
//! distributed across signers. The evaluator computes ||x - y||^2 without learning
//! the individual feature values.

use std::collections::HashMap;

use rand::thread_rng;

use examples::data::load_diabetes;
use mklhs::{
    api::{Scalar, keygen, scalar_zero},
    mkqhs_br_msq::{eval, sign, verify},
    params::Params,
    types::{Label, QuadProgramMsq, Tag},
};

const K: usize = 8;
const D: usize = 3;
const R: usize = (D + 1) / 2;
const N_SIGNERS: usize = 4;

fn main() {
    let pp = Params::<K>::new();
    let mut rng = thread_rng();
    let n = 2 * D;

    let dataset = load_diabetes();
    let feature_vecs: Vec<&Vec<f64>> = vec![&dataset.age, &dataset.bmi, &dataset.bp];
    let feature_names = ["age", "bmi", "bp"];

    use rand::Rng;
    let i = rng.gen_range(0..dataset.y.len());
    let j = rng.gen_range(0..dataset.y.len());
    eprintln!("Sampled patient indices: i={i}, j={j}");
    let x: Vec<u64> = feature_vecs.iter().map(|f| f[i].round() as u64).collect();
    let y: Vec<u64> = feature_vecs.iter().map(|f| f[j].round() as u64).collect();
    let msgs_scalar: Vec<Scalar> = x.iter().chain(y.iter()).map(|&v| Scalar::from(v)).collect();

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
    println!("Signing {n} messages ({D}-dimensional x and y, {N_SIGNERS} signers)...");
    let mut shares = Vec::with_capacity(n);
    let mut labels = Vec::with_capacity(n);
    for (i, &mi) in msgs_scalar.iter().enumerate() {
        let sk = &sks[i % N_SIGNERS];
        let mut tag_bytes = [0u8; K];
        tag_bytes.copy_from_slice(&(i as u64).to_le_bytes());
        let lab = Label::new(sk.id(), Tag(tag_bytes));
        let share = sign(&pp, sk, lab, mi).unwrap();
        shares.push(share);
        labels.push(lab);
    }

    // program construction
    let zero = scalar_zero();
    let one = Scalar::from(1u64);
    let neg_one = -one;
    let two = Scalar::from(2u64);

    let a = vec![zero; n];
    let mut b = vec![zero; n];
    let mut u_coeffs: Vec<[Scalar; R]> = vec![[zero; R]; n];
    let mut v_coeffs: Vec<[Scalar; R]> = vec![[zero; R]; n];

    for r in 1..=(D / 2) {
        let idx = r - 1;
        b[2 * r - 1] = two;
        b[2 * r - 1 + D] = two;
        u_coeffs[2 * r - 2][idx] = one;
        u_coeffs[2 * r - 1][idx] = one;
        u_coeffs[2 * r - 2 + D][idx] = neg_one;
        u_coeffs[2 * r - 1 + D][idx] = one;
        v_coeffs[2 * r - 2][idx] = one;
        v_coeffs[2 * r - 1][idx] = neg_one;
        v_coeffs[2 * r - 2 + D][idx] = neg_one;
        v_coeffs[2 * r - 1 + D][idx] = neg_one;
    }
    if D % 2 == 1 {
        let idx = R - 1;
        u_coeffs[D - 1][idx] = one;
        u_coeffs[2 * D - 1][idx] = neg_one;
        v_coeffs[D - 1][idx] = one;
        v_coeffs[2 * D - 1][idx] = neg_one;
    }

    let program = QuadProgramMsq::<K, R>::new(a, b, u_coeffs, v_coeffs, labels).unwrap();

    // evaluation
    println!("Evaluating...");
    let sig = eval(&pp, &program, shares).unwrap();

    // expected: ||x - y||^2 in both integers and field
    let dist_sq_int: u64 = x
        .iter()
        .zip(y.iter())
        .map(|(&xi, &yi)| {
            let d = xi as i64 - yi as i64;
            (d * d) as u64
        })
        .sum();
    let expected: Scalar = x
        .iter()
        .zip(y.iter())
        .map(|(&xi, &yi)| {
            let d = Scalar::from(xi) - Scalar::from(yi);
            d * d
        })
        .sum();

    // integer check: scalar result must equal integer result
    let integer_check = expected == Scalar::from(dist_sq_int);
    assert!(
        integer_check,
        "field result does not match integer computation"
    );

    // verification
    println!("Verifying...");
    let ok = verify(&pp, &program, &pks, expected, &sig).unwrap();

    println!();
    println!("── Reference: real computation ───────────────────────────");
    println!(
        "{:<8}  {:>10}  {:>10}  {:>10}",
        "feat",
        format!("x (p{i})"),
        format!("y (p{j})"),
        "(x-y)^2"
    );

    for (i, name) in feature_names.iter().enumerate() {
        let diff = x[i] as i64 - y[i] as i64;
        println!(
            "{:<8}  {:>10}  {:>10}  {:>10}",
            name,
            x[i],
            y[i],
            diff * diff
        );
    }
    println!("──────────────────────────────────────────────────────────");
    println!("||x - y||^2 = {dist_sq_int}");
    println!();
    println!("── Scheme: mkqhs-br-msq evaluated result ─────────────────");
    println!("Evaluated scalar (BLS12-381 Z_q) = {expected}");
    println!();
    println!("── Checks ────────────────────────────────────────────────");
    println!(
        "Scheme result == real result : {}",
        if integer_check { "PASS" } else { "FAIL" }
    );
    println!(
        "Cryptographic verification        : {}",
        if ok { "PASS" } else { "FAIL" }
    );
}
