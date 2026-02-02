//! Benchmarks for Poseidon2 AEAD encryption/decryption
//!
//! Run with: cargo bench --bench poseidon2_aead

use colossus_core::access_control::cryptography::ae_poseidon2::{
    POSEIDON2_KEY_SIZE, Poseidon2Aead,
};
use colossus_core::access_control::cryptography::traits::AE;
use cosmian_crypto_core::{
    CsRng, RandomFixedSizeCBytes, SymmetricKey, reexport::rand_core::SeedableRng,
};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

fn bench_poseidon2_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon2_aead_encrypt");

    // Test various payload sizes
    let sizes = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];

    for size in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut rng = CsRng::from_seed([42u8; 32]);
            let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::new(&mut rng);
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let aad = b"benchmark aad";

            b.iter(|| {
                let mut rng = CsRng::from_seed([42u8; 32]);
                Poseidon2Aead::encrypt(
                    black_box(&mut rng),
                    black_box(&key),
                    black_box(&plaintext),
                    black_box(aad),
                )
                .unwrap()
            })
        });
    }

    group.finish();
}

fn bench_poseidon2_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon2_aead_decrypt");

    // Test various payload sizes
    let sizes = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];

    for size in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut rng = CsRng::from_seed([42u8; 32]);
            let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::new(&mut rng);
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let aad = b"benchmark aad";

            // Pre-encrypt for decryption benchmark
            let ciphertext = Poseidon2Aead::encrypt(&mut rng, &key, &plaintext, aad).unwrap();

            b.iter(|| {
                Poseidon2Aead::decrypt(black_box(&key), black_box(&ciphertext), black_box(aad))
                    .unwrap()
            })
        });
    }

    group.finish();
}

fn bench_poseidon2_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon2_aead_roundtrip");

    let sizes = [32, 256, 1024, 4096];

    for size in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut rng = CsRng::from_seed([42u8; 32]);
            let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::new(&mut rng);
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let aad = b"benchmark aad";

            b.iter(|| {
                let mut rng = CsRng::from_seed([42u8; 32]);
                let ciphertext = Poseidon2Aead::encrypt(
                    black_box(&mut rng),
                    black_box(&key),
                    black_box(&plaintext),
                    black_box(aad),
                )
                .unwrap();
                Poseidon2Aead::decrypt(black_box(&key), black_box(&ciphertext), black_box(aad))
                    .unwrap()
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_poseidon2_encrypt,
    bench_poseidon2_decrypt,
    bench_poseidon2_roundtrip
);
criterion_main!(benches);
