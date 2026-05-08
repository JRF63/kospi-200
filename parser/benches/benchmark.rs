use criterion::{Criterion, criterion_group, criterion_main};
use kospi_parser::{
    OUTPUT_LEN, PcapIterator, QuoteIterator, SortedQuoteIteratorBuckets, SortedQuoteIteratorHeap,
    Timestamp, open_mmaped_file,
};
use std::{
    hint::black_box,
    io::{BufWriter, Write},
    time::Duration,
};

fn criterion_config() -> Criterion {
    Criterion::default().measurement_time(Duration::from_secs(10))
}

fn criterion_benchmark(c: &mut Criterion) {
    const STDOUT_BUF_SIZE: usize = 128 * 1024;
    const BUCKET_INIT_CAPACITY: usize = 32;
    let filename = "../dataset/mdf-kospi200.20110216-0.pcap";

    c.bench_function("parse_hhmmssuu", |b| {
        b.iter(|| Timestamp::parse_hhmmssuu(black_box(b"12304580")))
    });

    c.bench_function("PCAP iterator", |b| {
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let iterator = PcapIterator::new(&mmap);
            iterator.for_each(|p| {
                black_box(p);
            });
        })
    });
    c.bench_function("quote iterator", |b| {
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let pcap_iterator = PcapIterator::new(&mmap);
            let quote_iterator = QuoteIterator::new(pcap_iterator);
            quote_iterator.for_each(|p| {
                black_box(p.into_quote().to_line_bytes());
            });
        })
    });
    c.bench_function("sorted quote iterator (heap)", |b| {
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let pcap_iterator = PcapIterator::new(&mmap);
            let quote_iterator =
                SortedQuoteIteratorHeap::with_capacity(QuoteIterator::new(pcap_iterator), 3000);
            quote_iterator.for_each(|p| {
                black_box(p.to_line_bytes());
            });
        })
    });
    c.bench_function("sorted quote iterator (buckets)", |b| {
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let pcap_iterator = PcapIterator::new(&mmap);
            let quote_iterator = SortedQuoteIteratorBuckets::with_capacity(
                QuoteIterator::new(pcap_iterator),
                BUCKET_INIT_CAPACITY,
            );
            quote_iterator.for_each(|p| {
                black_box(p.to_line_bytes());
            });
        })
    });
    c.bench_function("printing", |b| {
        let _print_gag = gag::Gag::stdout().unwrap();
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let pcap_iterator = PcapIterator::new(&mmap);
            let quote_iterator = SortedQuoteIteratorBuckets::with_capacity(
                QuoteIterator::new(pcap_iterator),
                BUCKET_INIT_CAPACITY,
            );

            let mut writer = BufWriter::with_capacity(STDOUT_BUF_SIZE, std::io::stdout().lock());
            for quote in quote_iterator {
                let line = quote.to_line_bytes();
                writer.write_all(&line).unwrap();
            }
        })
    });
    c.bench_function("printing (zero-copy)", |b| {
        let _print_gag = gag::Gag::stdout().unwrap();
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let pcap_iterator = PcapIterator::new(&mmap);
            let mut quote_iterator = SortedQuoteIteratorBuckets::with_capacity(
                QuoteIterator::new(pcap_iterator),
                BUCKET_INIT_CAPACITY,
            );

            const BUF_LEN: usize = (STDOUT_BUF_SIZE / OUTPUT_LEN) * OUTPUT_LEN;
            let mut output_buf = vec![b' '; BUF_LEN];
            let mut stdout = std::io::stdout().lock();

            loop {
                output_buf.fill(b' ');
                let (chunks, _remainder) = output_buf.as_chunks_mut::<OUTPUT_LEN>();

                let mut offset = 0;
                for line_buf in chunks {
                    if let Some(quote) = quote_iterator.next() {
                        quote.write_line_bytes(line_buf);
                        offset += OUTPUT_LEN;
                    } else {
                        break;
                    }
                }

                if offset == BUF_LEN {
                    stdout.write_all(&output_buf).unwrap();
                } else {
                    stdout.write_all(&output_buf[..offset]).unwrap();
                    break;
                }
            }
        })
    });

    // This is slower than printing and the gap worsens when the input size is increased
    c.bench_function("multithreaded best case", |b| {
        use rayon::{
            ThreadPoolBuilder,
            iter::{ParallelBridge, ParallelIterator},
        };

        ThreadPoolBuilder::new().build_global().unwrap_or(());
        b.iter(|| {
            let mmap = open_mmaped_file(black_box(filename)).unwrap();
            let pcap_iterator = PcapIterator::new(&mmap);

            // This doesn't even filter the packets
            pcap_iterator.par_bridge().for_each(|p| {
                black_box(p);
            });
        })
    });
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = criterion_benchmark
}
criterion_main!(benches);
