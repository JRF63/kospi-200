use clap::Parser;
use std::io::Write;

use kospi_parser::{
    OUTPUT_LEN, PcapIterator, Quote, QuoteIterator, SortedQuoteIteratorBuckets, open_mmaped_file,
};

#[derive(Parser)]
struct Args {
    /// Reorder the messages according to the quote accept time
    #[arg(short)]
    reorder: bool,

    /// Filename of the PCAP file
    input: String,
}

fn print_quotes<'a>(mut quote_iterator: impl Iterator<Item = Quote<'a>>) -> std::io::Result<()> {
    const STDOUT_BUF_SIZE: usize = 128 * 1024; // Use a large value to minimize syscalls
    const BUF_LEN: usize = (STDOUT_BUF_SIZE / OUTPUT_LEN) * OUTPUT_LEN;

    let mut output_buf = vec![0u8; BUF_LEN];
    let mut stdout = std::io::stdout().lock();

    loop {
        // Set the buffer to all spaces. This is for the quantity@price strings, the rest of the
        // fields have constant length.
        output_buf.fill(b' ');

        let (chunks, _remainder) = output_buf.as_chunks_mut::<OUTPUT_LEN>();

        let mut offset = 0;
        for line_buf in chunks {
            if let Some(quote) = quote_iterator.next() {
                quote.write_line_bytes(line_buf);
                offset += OUTPUT_LEN;
            } else {
                // Else the iterator is empty
                break;
            }
        }

        if offset == BUF_LEN {
            stdout.write_all(&output_buf).unwrap();
        } else {
            // If `offset != BUF_LEN` there was a break in the for-loop above and `quote_iterator`
            // is already finished.
            // `offset` <= `BUF_LEN` but it's unlikely that rustc could deduce that constraint. The
            //  slice op here could be replaced with `get_unchecked` but it's not done because this
            // branch only matters for the very last write.
            stdout.write_all(&output_buf[..offset]).unwrap();
            break;
        }
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let mmap = open_mmaped_file(args.input)?;
    let pcap_iterator = PcapIterator::new(&mmap);

    if args.reorder {
        const BUCKET_INIT_CAPACITY: usize = 32;
        let quote_iterator = SortedQuoteIteratorBuckets::with_capacity(
            QuoteIterator::new(pcap_iterator),
            BUCKET_INIT_CAPACITY,
        );

        // Prints the quote in order of ascending accept time
        print_quotes(quote_iterator)?;
    } else {
        let quote_iterator = QuoteIterator::new(pcap_iterator);

        // Prints the quotes in the order they appear on the file
        print_quotes(quote_iterator.map(|p| p.into_quote()))?;
    }

    Ok(())
}
