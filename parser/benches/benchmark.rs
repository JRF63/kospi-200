use criterion::{Criterion, criterion_group, criterion_main};
use kospi_parser::{PcapIterator, Timestamp, build_quote_iterator, open_mmaped_file};
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parse_hhmmssuu", |b| {
        b.iter(|| Timestamp::parse_hhmmssuu(black_box(b"12304580")))
    });
    c.bench_function("PCAP iterator", |b| {
        b.iter(|| {
            let mmap =
                open_mmaped_file(black_box("../dataset/mdf-kospi200.20110216-0.pcap")).unwrap();
            let iterator = PcapIterator::new(&mmap);
            iterator.count()
        })
    });
    c.bench_function("quote iterator", |b| {
        b.iter(|| {
            let mmap =
                open_mmaped_file(black_box("../dataset/mdf-kospi200.20110216-0.pcap")).unwrap();
            let pcap_iterator = PcapIterator::new(&mmap);
            let quote_iterator = build_quote_iterator(pcap_iterator);
            quote_iterator.count()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
