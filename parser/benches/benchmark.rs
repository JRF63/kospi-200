use criterion::{Criterion, criterion_group, criterion_main};
use kospi_parser::{
    PcapIterator, QuoteIterator, SortedQuoteIterator2, Timestamp, open_mmaped_file,
};
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parse_hhmmssuu", |b| {
        b.iter(|| Timestamp::parse_hhmmssuu(black_box(b"12304580")))
    });

    let filename = "../dataset/mdf-kospi200.20110216-0.pcap";

    c.bench_function("PCAP iterator", |b| {
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let iterator = PcapIterator::new(&mmap);
            iterator.count()
        })
    });
    // The extra work compared to the above is in the single digit nanosecond range. Probably not
    // worth parallelizing.
    c.bench_function("quote iterator", |b| {
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let pcap_iterator = PcapIterator::new(&mmap);
            let quote_iterator = QuoteIterator::new(pcap_iterator);
            let lines = quote_iterator.map(|x| x.to_line_bytes());
            lines.count()
        })
    });

    c.bench_function("sorted quote iterator", |b| {
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let pcap_iterator = PcapIterator::new(&mmap);
            let quote_iterator = SortedQuoteIterator2::new(pcap_iterator, 3000);
            let lines = quote_iterator.map(|x| x.to_line_bytes());
            lines.count()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
