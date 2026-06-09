//! Cycle-count benchmark for mklhs using criterion + CyclesPerByte.
//!
//! Run:  cargo bench --bench mklhs_cycles

use std::collections::HashMap;

use ark_std::{UniformRand, test_rng};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use criterion_cycles_per_byte::CyclesPerByte;

use mkqhs::{
    api::Scalar,
    mklhs::{eval, keygen, sign, verify},
    params::Params,
    types::{Label, LabeledProgram, Tag},
};

const K: usize = 8;
const T_VALUES: &[usize] = &[2, 5, 10];
const MSGS_PER_SIGNER: usize = 16;

fn bench_keygen(c: &mut Criterion<CyclesPerByte>) {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    c.bench_function("mklhs/keygen", |b| {
        b.iter(|| keygen(&pp, &mut rng).unwrap())
    });
}

fn bench_sign(c: &mut Criterion<CyclesPerByte>) {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk, _) = keygen(&pp, &mut rng).unwrap();
    let msg = Scalar::rand(&mut rng);
    let lab = Label::new(sk.id(), Tag([0u8; K]));
    c.bench_function("mklhs/sign", |b| {
        b.iter(|| sign(&pp, &sk, lab, msg).unwrap())
    });
}

fn bench_eval_verify(c: &mut Criterion<CyclesPerByte>) {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let mut group = c.benchmark_group("mklhs");
    // group.sample_size(100);
    group.measurement_time(std::time::Duration::from_secs(20));

    for &t in T_VALUES {
        let n = t * MSGS_PER_SIGNER;
        let mut sks = Vec::new();
        let mut pks = HashMap::new();
        for _ in 0..t {
            let (sk, pk) = keygen(&pp, &mut rng).unwrap();
            pks.insert(pk.id(), pk);
            sks.push(sk);
        }
        let msgs: Vec<Scalar> = (0..n).map(|_| Scalar::rand(&mut rng)).collect();
        let mut labels = Vec::new();
        let mut shares_base = Vec::new();
        for i in 0..t {
            for j in 0..MSGS_PER_SIGNER {
                let idx = i * MSGS_PER_SIGNER + j;
                let lab = Label::new(sks[i].id(), Tag((idx as u64).to_le_bytes()));
                labels.push(lab);
                shares_base.push(sign(&pp, &sks[i], lab, msgs[idx]).unwrap());
            }
        }
        let coeffs: Vec<Scalar> = (0..n).map(|_| Scalar::rand(&mut rng)).collect();
        let expected: Scalar = (0..n).map(|i| coeffs[i] * msgs[i]).sum();
        let program = LabeledProgram::new(coeffs, labels).unwrap();

        group.bench_with_input(BenchmarkId::new("eval", format!("t={t}")), &t, |b, _| {
            b.iter_batched(
                || shares_base.clone(),
                |s| eval(&pp, &program, s).unwrap(),
                BatchSize::SmallInput,
            )
        });

        let sig = eval(&pp, &program, shares_base.clone()).unwrap();
        group.bench_with_input(BenchmarkId::new("verify", format!("t={t}")), &t, |b, _| {
            b.iter(|| verify(&pp, &program, &pks, expected, &sig).unwrap())
        });
    }
    group.finish();
}

criterion_group!(
    name = keygen_sign;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_keygen, bench_sign
);
criterion_group!(
    name = eval_verify;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_eval_verify
);
criterion_main!(keygen_sign, eval_verify);
