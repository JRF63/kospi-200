use clap::Parser;
use std::io::{BufWriter, Write};

use kospi_parser::{PcapIterator, QuoteIterator, SortedQuoteIteratorBuckets, open_mmaped_file};

const STDOUT_BUF_SIZE: usize = 128 * 1024; // Use a large value to minimize syscalls

#[derive(Parser)]
struct Args {
    /// Reorder the messages according to the quote accept time
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
        let quote_iterator = SortedQuoteIteratorBuckets::new(pcap_iterator);

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
