mod ethernet;
mod ip;
mod pcap;
mod quote;
mod udp;

use clap::Parser;
use memmap2::Mmap;
use std::{collections::BinaryHeap, fs::File, path::Path};

use self::{
    ethernet::EthernetPacket,
    ip::IpPacket,
    pcap::{PcapIterator, PcapPacket},
    quote::QuotePacket,
    udp::UdpPacket,
};

const GLOBAL_HEADER_SIZE: usize = 24;
const PACKET_HEADER_SIZE: usize = 16;
const ETHERNET_HEADER_SIZE: usize = 14;
const IPV6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;
const QUOTE_PACKET_SIZE: usize = 215;

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
const PROTOCOL_NUMBER_UDP: u8 = 0x11;

#[derive(Parser)]
struct Args {
    /// Whether to reorder the messages according to the quote accept time
    #[arg(short)]
    reorder: bool,

    /// Filename of the PCAP file
    input: String,
}

// Helper function for getting a fixed sized array from a slice.
// This is used for converting to a u16/u32/u64 (minding the endianness).
fn convert_with_offset<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let bytes = data.get(offset..)?;
    bytes.first_chunk::<N>().copied()
}

fn open_mmaped_file<P>(path: P) -> std::io::Result<Mmap>
where
    P: AsRef<Path>,
{
    let file = File::open(path)?;

    // SAFETY: Safe assuming no other process modifies the underlying file
    unsafe { Mmap::map(&file) }
}

fn build_quote_iterator<'a>(
    pcap_iterator: PcapIterator<'a>,
    base_timestamp: &mut Option<i64>,
) -> impl Iterator<Item = QuotePacket<'a>> {
    pcap_iterator.enumerate().filter_map(|(seq_num, p)| {
        let PcapPacket {
            ts_sec,
            ts_usec,
            data,
        } = p;
        let EthernetPacket { ether_type, data } = EthernetPacket::new(data)?;
        let IpPacket { protocol, data } = IpPacket::new(ether_type, data)?;

        // Only accept UDP packets
        if protocol == PROTOCOL_NUMBER_UDP {
            let UdpPacket { dst_port, data } = UdpPacket::new(data)?;

            match dst_port {
                15515..=15516 => {
                    let pkt_time = (ts_sec as i64 * 1_000_000) + (ts_usec as i64);
                    QuotePacket::new(seq_num, pkt_time, data, base_timestamp)
                }
                _ => None, // Reject packets not on ports 15515 and 15516
            }
        } else {
            None
        }
    })
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let mmap = open_mmaped_file(args.input)?;

    // Timestamp of midnight + drift between PCAP and the exchange
    let mut base_timestamp: Option<i64> = None;

    let quote_iterator = build_quote_iterator(PcapIterator::new(&mmap), &mut base_timestamp);

    if args.reorder {
        let mut heap: BinaryHeap<QuotePacket<'_>> = BinaryHeap::new();

        for quote in quote_iterator {
            const THREE_SECONDS: i64 = 3_000_000; // 3 million microseconds

            if let Some(oldest) = heap.peek()
                && quote.pkt_time - oldest.accept_time >= THREE_SECONDS
            {
                let quote = heap.pop().unwrap();
                print_quote(&quote);
            }

            heap.push(quote);
        }

        // Print the remaining quotes
        while let Some(quote) = heap.pop() {
            print_quote(&quote);
        }
    } else {
        for quote in quote_iterator {
            print_quote(&quote);
        }
    }

    Ok(())
}

#[rustfmt::skip]
fn print_quote(quote: &QuotePacket<'_>) {
    println!(
        concat!(
            "{} {} {} ",
            "{:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} ",
            "{:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5}"
        ),
        quote.pkt_time(), quote.accept_time_str(), quote.issue_code(),
        quote.bid_5_quantity(), quote.bid_5_price(),
        quote.bid_4_quantity(), quote.bid_4_price(),
        quote.bid_3_quantity(), quote.bid_3_price(),
        quote.bid_2_quantity(), quote.bid_2_price(),
        quote.bid_1_quantity(), quote.bid_1_price(),
        quote.ask_1_quantity(), quote.ask_1_price(),
        quote.ask_2_quantity(), quote.ask_2_price(),
        quote.ask_3_quantity(), quote.ask_3_price(),
        quote.ask_4_quantity(), quote.ask_4_price(),
        quote.ask_5_quantity(), quote.ask_5_price(),
    );
}
