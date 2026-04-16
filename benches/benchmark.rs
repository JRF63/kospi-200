use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tsuru_challenge::Timestamp;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parse_hhmmssuu", |b| {
        b.iter(|| Timestamp::parse_hhmmssuu(black_box(b"12304580")))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
