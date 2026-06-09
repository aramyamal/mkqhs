//! Cycle-count benchmark for mkqhs-cbr-msq using criterion + CyclesPerByte.
//!
//! Run:  cargo bench --bench mkqhs_cbr_msq_cycles

use std::collections::HashMap;

use ark_std::{UniformRand, test_rng};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use criterion_cycles_per_byte::CyclesPerByte;

use mkqhs::{
    api::Scalar,
    mkqhs_cbr_msq::{eval, keygen, sign, verify},
    params::Params,
    types::{Label, QuadProgramMsq, Tag},
};

const K: usize = 8;
const T_VALUES: &[usize] = &[2, 5, 10];
const MSGS_PER_SIGNER: usize = 16;

fn bench_keygen(c: &mut Criterion<CyclesPerByte>) {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    c.bench_function("mkqhs_cbr_msq/keygen", |b| {
        b.iter(|| keygen(&pp, &mut rng).unwrap())
    });
}

fn bench_sign(c: &mut Criterion<CyclesPerByte>) {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk, _) = keygen(&pp, &mut rng).unwrap();
    let msg = Scalar::rand(&mut rng);
    let lab = Label::new(sk.id(), Tag([0u8; K]));
    c.bench_function("mkqhs_cbr_msq/sign", |b| {
        b.iter(|| sign(&pp, &sk, lab, msg).unwrap())
    });
}

macro_rules! bench_for_r {
    ($fn_name:ident, $r:literal) => {
        fn $fn_name(c: &mut Criterion<CyclesPerByte>) {
            let pp = Params::<K>::new();
            let mut rng = test_rng();
            let mut group = c.benchmark_group(concat!("mkqhs_cbr_msq/R=", stringify!($r)));
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
                let u_mat: Vec<[Scalar; $r]> = (0..n)
                    .map(|_| std::array::from_fn(|_| Scalar::rand(&mut rng)))
                    .collect();
                let v_mat: Vec<[Scalar; $r]> = (0..n)
                    .map(|_| std::array::from_fn(|_| Scalar::rand(&mut rng)))
                    .collect();
                let a_coeffs: Vec<Scalar> = (0..n).map(|_| Scalar::rand(&mut rng)).collect();
                let b_coeffs: Vec<Scalar> = (0..n).map(|_| Scalar::rand(&mut rng)).collect();
                let expected: Scalar = (0..$r)
                    .map(|r| {
                        let lu: Scalar = (0..n).map(|i| u_mat[i][r] * msgs[i]).sum();
                        let lv: Scalar = (0..n).map(|i| v_mat[i][r] * msgs[i]).sum();
                        lu * lv
                    })
                    .sum::<Scalar>()
                    + (0..n)
                        .map(|i| a_coeffs[i] * msgs[i] + b_coeffs[i] * msgs[i] * msgs[i])
                        .sum::<Scalar>();
                let program =
                    QuadProgramMsq::<K, $r>::new(a_coeffs, b_coeffs, u_mat, v_mat, labels).unwrap();

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
    };
}

bench_for_r!(bench_r1, 1);
bench_for_r!(bench_r2, 2);
bench_for_r!(bench_r4, 4);
bench_for_r!(bench_r8, 8);
// bench_for_r!(bench_r16, 16);

criterion_group!(
    name = keygen_sign;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_keygen, bench_sign
);
criterion_group!(
    name = r1;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_r1
);
criterion_group!(
    name = r2;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_r2
);
criterion_group!(
    name = r4;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_r4
);
criterion_group!(
    name = r8;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_r8
);

// criterion_group!(
//     name = r16;
//     config = Criterion::default().with_measurement(CyclesPerByte);
//     targets = bench_r16
// );
// criterion_main!(keygen_sign, r1, r2, r4, r8, r16);

criterion_main!(keygen_sign, r1, r2, r4, r8);
