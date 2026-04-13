mod ethernet;
mod ip;
mod pcap;
mod quote;
mod udp;

use clap::Parser;
use memmap2::Mmap;
use std::{cell::OnceCell, collections::BinaryHeap, fs::File, io::BufWriter, path::Path};

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

const HOUR_MICROS: i64 = 3_600_000_000;
const MIN_MICROS: i64 = 60_000_000;
const SEC_MICROS: i64 = 1_000_000;
const CENT_MICROS: i64 = 10_000;

const TIMEZONE_OFFSET: i64 = 9 * HOUR_MICROS; // KRX is GMT +9

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
    base_timestamp: &OnceCell<i64>,
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

    // Timestamp of GMT +9 midnight. Using a `OnceCell` because this needs to be simultaneously used by the
    // iterator and the printing logic
    let base_timestamp: OnceCell<i64> = OnceCell::new();

    let quote_iterator = build_quote_iterator(PcapIterator::new(&mmap), &base_timestamp);

    let mut writer = BufWriter::new(std::io::stdout().lock());

    if args.reorder {
        let mut heap: BinaryHeap<QuotePacket<'_>> = BinaryHeap::new();

        for quote in quote_iterator {
            if let Some(earliest) = heap.peek() {
                // If the 3 second delay has passed
                if quote.pkt_time_utc - earliest.accept_time_utc >= 3 * SEC_MICROS {
                    let earliest = heap.pop().unwrap();
                    earliest.write_line(&mut writer, *base_timestamp.get().unwrap())?;
                }
            }

            heap.push(quote);
        }

        // Print the remaining quotes
        while let Some(quote) = heap.pop() {
            quote.write_line(&mut writer, *base_timestamp.get().unwrap())?;
        }
    } else {
        for quote in quote_iterator {
            quote.write_line(&mut writer, *base_timestamp.get().unwrap())?;
        }
    }

    Ok(())
}
