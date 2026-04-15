mod ethernet;
mod ip;
mod pcap;
mod quote;
mod time;
mod udp;

use clap::Parser;
use memmap2::Mmap;
use std::{collections::BinaryHeap, fs::File, io::BufWriter, path::Path};

use self::{
    ethernet::EthernetPacket,
    ip::IpPacket,
    pcap::{PcapIterator, PcapPacket},
    quote::QuotePacket,
    time::Timestamp,
    udp::UdpPacket,
};

const GLOBAL_HEADER_SIZE: usize = 24;
const PACKET_HEADER_SIZE: usize = 16;
const ETHERNET_HEADER_SIZE: usize = 14;
const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;
const QUOTE_PACKET_SIZE: usize = 215;

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
const PROTOCOL_NUMBER_UDP: u8 = 0x11;

const APPROX_PACKETS_PER_SEC: usize = 1000; // Assume 1000 packets per second
const INITIAL_HEAP_CAPACITY: usize = 3 * APPROX_PACKETS_PER_SEC; // 3 second buffer

#[derive(Parser)]
struct Args {
    /// Whether to reorder the messages according to the quote accept time
    #[arg(short)]
    reorder: bool,

    /// Filename of the PCAP file
    input: String,
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
) -> impl Iterator<Item = QuotePacket<'a>> {
    pcap_iterator.enumerate().filter_map(|(seq_num, p)| {
        let PcapPacket { pkt_time, data } = p;
        let EthernetPacket { ether_type, data } = EthernetPacket::new(data)?;
        let IpPacket { protocol, data } = IpPacket::new(ether_type, data)?;

        // Only accept UDP packets
        if protocol == PROTOCOL_NUMBER_UDP {
            let UdpPacket { dst_port, data } = UdpPacket::new(data)?;

            match dst_port {
                15515..=15516 => QuotePacket::new(seq_num, pkt_time, data),
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

    let quote_iterator = build_quote_iterator(PcapIterator::new(&mmap));

    let mut writer = BufWriter::new(std::io::stdout().lock());

    if args.reorder {
        let mut heap: BinaryHeap<QuotePacket<'_>> =
            BinaryHeap::with_capacity(INITIAL_HEAP_CAPACITY);

        for quote in quote_iterator {
            if let Some(earliest) = heap.peek() {
                // If the 3 second delay has passed
                if quote.pkt_time - earliest.accept_time >= Timestamp::from_secs_and_nanos(3, 0) {
                    let earliest = heap.pop().unwrap();
                    earliest.write_line(&mut writer)?;
                }
            }

            heap.push(quote);
        }

        // Print the remaining quotes
        while let Some(quote) = heap.pop() {
            quote.write_line(&mut writer)?;
        }
    } else {
        for quote in quote_iterator {
            quote.write_line(&mut writer)?;
        }
    }

    Ok(())
}
