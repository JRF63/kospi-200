use clap::Parser;
use std::io::{BufWriter, Write};

use kospi_parser::{PcapIterator, QuoteIterator, SortedQuoteIteratorHeap, open_mmaped_file};

const APPROX_PACKETS_PER_SEC: usize = 1000; // Assume 1000 packets per second
const INITIAL_HEAP_CAPACITY: usize = 3 * APPROX_PACKETS_PER_SEC; // 3 second buffer
const STDOUT_BUF_SIZE: usize = 128_000; // Use a large value to minimize syscalls

#[derive(Parser)]
struct Args {
    /// Whether to reorder the messages according to the quote accept time
    #[arg(short)]
    reorder: bool,

    /// Filename of the PCAP file
    input: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let mmap = open_mmaped_file(args.input)?;
    let pcap_iterator = PcapIterator::new(&mmap);

    let mut writer = BufWriter::with_capacity(STDOUT_BUF_SIZE, std::io::stdout().lock());

    if args.reorder {
        let quote_iterator = SortedQuoteIteratorHeap::new(pcap_iterator, INITIAL_HEAP_CAPACITY);

        // Prints the quote in order of ascending accept time
        for quote in quote_iterator {
            let line = quote.to_line_bytes();
            writer.write_all(&line)?;
        }
    } else {
        let quote_iterator = QuoteIterator::new(pcap_iterator);

        // Prints the quotes in the order they appear on the file
        for quote in quote_iterator {
            let line = quote.into_quote().to_line_bytes();
            writer.write_all(&line)?;
        }
    }

    Ok(())
}
