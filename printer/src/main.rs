use clap::Parser;
use std::{
    collections::BinaryHeap,
    io::{BufWriter, Write},
};

use kospi_parser::{PcapIterator, QuotePacket, Timestamp, build_quote_iterator, open_mmaped_file};

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

    let quote_iterator = build_quote_iterator(PcapIterator::new(&mmap));

    let mut writer = BufWriter::with_capacity(STDOUT_BUF_SIZE, std::io::stdout().lock());

    if args.reorder {
        // Stores the quotes in order of increasing accept time
        let mut heap: BinaryHeap<QuotePacket<'_>> =
            BinaryHeap::with_capacity(INITIAL_HEAP_CAPACITY);

        for quote in quote_iterator {
            if let Some(earliest) = heap.peek() {
                // If the 3 second delay has passed, print the earliest quote in the heap
                if quote.pkt_time - earliest.accept_time >= Timestamp::from_secs_and_nanos(3, 0) {
                    let earliest = heap.pop().unwrap();
                    let line = earliest.to_line_bytes();
                    writer.write_all(&line)?;
                }
            }

            heap.push(quote);
        }

        // Print the remaining quotes
        while let Some(quote) = heap.pop() {
            let line = quote.to_line_bytes();
            writer.write_all(&line)?;
        }
    } else {
        // Prints the quotes in the order they appear on the file
        for quote in quote_iterator {
            let line = quote.to_line_bytes();
            writer.write_all(&line)?;
        }
    }

    Ok(())
}
