use clap::Parser;
use memmap2::Mmap;
use std::{fs::File, iter::Iterator};

#[derive(Parser)]
struct Args {
    /// Whether to reorder the messages according to the quote accept time
    #[arg(short)]
    reorder: bool,

    /// Filename of the PCAP file
    input: String,
}

const GLOBAL_HEADER_SIZE: usize = 24;
const PACKET_HEADER_SIZE: usize = 16;
const ETHERNET_HEADER_SIZE: usize = 14;
const IPV6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;
const QUOTE_PACKET_SIZE: usize = 215;

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
const PROTOCOL_NUMBER_UDP: u8 = 0x11;

struct Quote<'a> {
    pkt_time: u64,
    data: &'a [u8; QUOTE_PACKET_SIZE],
}

impl<'a> Quote<'a> {
    // Pass `START` and `END` as compile time constants to optimize out bounds checking during slicing
    fn parse_as_ascii_string<const START: usize, const END: usize>(&'a self) -> &'a str {
        // SAFETY: We assume this is proper alphanumeric ASCII
        unsafe { std::str::from_utf8_unchecked(&self.data[START..END]) }
    }

    fn parse_as_ascii_string_and_trim<const START: usize, const END: usize>(&'a self) -> &'a str {
        let alphanum_str = self.parse_as_ascii_string::<START, END>();
        let trimmed = alphanum_str.trim_start_matches('0');

        // Avoid empty strings when the price or quantity is all zero
        if trimmed.is_empty() { "0" } else { trimmed }
    }

    fn pkt_time(&'a self) -> u64 {
        self.pkt_time
    }

    fn accept_time(&'a self) -> &'a str {
        self.parse_as_ascii_string::<206, 214>()
    }

    fn issue_code(&'a self) -> &'a str {
        self.parse_as_ascii_string::<5, 17>()
    }
}

macro_rules! generate_getters {
    ($($name:ident, $start:expr, $end:expr);*) => {
        impl<'a> Quote<'a> {
            $(
                pub fn $name(&'a self) -> &'a str {
                    self.parse_as_ascii_string_and_trim::<$start, $end>()
                }
            )*
        }
    }
}

generate_getters! {
    bid_1_price, 29, 34;
    bid_1_quantity, 34, 41;

    bid_2_price, 41, 46;
    bid_2_quantity, 46, 53;

    bid_3_price, 53, 58;
    bid_3_quantity, 58, 65;

    bid_4_price, 65, 70;
    bid_4_quantity, 70, 77;

    bid_5_price, 77, 82;
    bid_5_quantity, 82, 89;

    ask_1_price, 96, 101;
    ask_1_quantity, 101, 108;

    ask_2_price, 108, 113;
    ask_2_quantity, 113, 120;

    ask_3_price, 120, 125;
    ask_3_quantity, 125, 132;

    ask_4_price, 132, 137;
    ask_4_quantity, 137, 144;

    ask_5_price, 144, 149;
    ask_5_quantity, 149, 156
}

struct QuoteIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> QuoteIterator<'a> {
    fn new(data: &'a [u8]) -> QuoteIterator<'a> {
        // Timestamp is in microseconds and is little endian
        assert_eq!(
            u32::from_le_bytes(data[0..4].try_into().unwrap()),
            0xa1b2c3d4
        );

        // Should be ethernet
        assert_eq!(u32::from_le_bytes(data[20..24].try_into().unwrap()), 1);

        QuoteIterator {
            data,
            offset: GLOBAL_HEADER_SIZE, // Skip global header
        }
    }
}

// Helper function used in QuoteIterator::next()
fn convert_with_offset<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let bytes = data.get(offset..(offset + N))?;
    debug_assert_eq!(bytes.len(), N);

    // SAFETY: `bytes` is exactly `N` bytes long
    Some(unsafe { bytes.try_into().unwrap_unchecked() })
}

impl<'a> Iterator for QuoteIterator<'a> {
    type Item = Quote<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.data.len() {
            // * PCAP Packet Header (16 bytes)
            // +---------+--------+----------+------------------------------------------+
            // | Indices | Size   | Field    | Description                              |
            // +---------+--------+----------+------------------------------------------+
            // | 0..4    | 4      | ts_sec   | Timestamp: Seconds since Epoch           |
            // | 4..8    | 4      | ts_usec  | Timestamp: Microseconds                  |
            // | 8..12   | 4      | cap_len  | Number of bytes actually saved in file   |
            // | 12..16  | 4      | orig_len | Original length of packet on the wire    |
            // +---------+--------+----------+------------------------------------------+
            let pkt_header: &[u8; PACKET_HEADER_SIZE] = {
                let header_bytes: &[u8] = self
                    .data
                    .get(self.offset..(self.offset + PACKET_HEADER_SIZE))?; // Returns `None` if slicing fails

                // SAFETY: The byte slice is exactly `PACKET_HEADER_SIZE` long
                unsafe { header_bytes.try_into().unwrap_unchecked() }
            };

            // The following `unwrap`s should be optimized out since `pkt_header` is a `&[u8; 16]`
            let ts_sec = u32::from_le_bytes(pkt_header[0..4].try_into().unwrap());
            let ts_usec = u32::from_le_bytes(pkt_header[4..8].try_into().unwrap());
            let cap_len = u32::from_le_bytes(pkt_header[8..12].try_into().unwrap()) as usize;

            let (protocol, ip_header_size) = {
                // PCAP Packet Header (16 bytes)
                // * Ethernet Header (14 bytes)
                // +---------+--------+-----------+-----------------------------------------+
                // | Indices | Size   | Field     | Value / Description                     |
                // +---------+--------+-----------+-----------------------------------------+
                // | 0..6    | 6      | dst_mac   | Destination MAC                         |
                // | 6..12   | 6      | src_mac   | Source MAC                              |
                // | 12..14  | 2      | type      | EtherType                               |
                // +---------+--------+-----------+-----------------------------------------+
                let ether_type = u16::from_be_bytes({
                    convert_with_offset::<2>(self.data, self.offset + PACKET_HEADER_SIZE + 12)?
                });

                match ether_type {
                    ETHER_TYPE_IPV4 => {
                        // PCAP Packet Header (16 bytes)
                        // Ethernet Header (14 bytes)
                        // * IPv4 Header (20 bytes minimum)
                        // +---------+--------+-----------+-----------------------------------------+
                        // | Offset  | Size   | Field     | Description                             |
                        // +---------+--------+-----------+-----------------------------------------+
                        // | 0       | 1      | ver_ihl   | Version (4) & Header Length (IHL)       |
                        // | 1       | 1      | tos       | Type of Service                         |
                        // | 2..4    | 2      | total_len | Total length of IP packet               |
                        // | 4..6    | 2      | id        | Identification                          |
                        // | 6..8    | 2      | flags_off | Flags and Fragment Offset               |
                        // | 8       | 1      | ttl       | Time to Live                            |
                        // | 9       | 1      | protocol  | Protocol                                |
                        // | 10..12  | 2      | checksum  | Header Checksum                         |
                        // | 12..16  | 4      | src_ip    | Source IP Address                       |
                        // | 16..20  | 4      | dst_ip    | Destination IP Address                  |
                        // +---------+--------+-----------+-----------------------------------------+
                        let ver_ihl = u8::from_be_bytes(convert_with_offset::<1>(
                            self.data,
                            self.offset + PACKET_HEADER_SIZE + ETHERNET_HEADER_SIZE,
                        )?);
                        let ihl = ver_ihl & 0b1111;
                        let header_size = (ihl as usize) * 4;

                        let protocol = u8::from_be_bytes(convert_with_offset::<1>(
                            self.data,
                            self.offset + PACKET_HEADER_SIZE + ETHERNET_HEADER_SIZE + 9,
                        )?);

                        (protocol, header_size)
                    }
                    ETHER_TYPE_IPV6 => {
                        // PCAP Packet Header (16 bytes)
                        // Ethernet Header (14 bytes)
                        // * IPv6 Header (40 bytes)
                        // +---------+--------+-----------+-----------------------------------------+
                        // | Offset  | Size   | Field     | Description                             |
                        // +---------+--------+-----------+-----------------------------------------+
                        // | 0..4    | 4      | ver_tc_fl | Version(6), Traffic Class, Flow Label   |
                        // | 4..6    | 2      | payload_ln| Payload Length (UDP Header + Data)      |
                        // | 6       | 1      | next_hdr  | Next Header                             |
                        // | 7       | 1      | hop_limit | Hop Limit (TTL)                         |
                        // | 8..24   | 16     | src_ip    | 128-bit Source Address                  |
                        // | 24..40  | 16     | dst_ip    | 128-bit Destination Address             |
                        // +---------+--------+-----------+-----------------------------------------+
                        let protocol = u8::from_be_bytes(convert_with_offset::<1>(
                            self.data,
                            self.offset + PACKET_HEADER_SIZE + ETHERNET_HEADER_SIZE + 6,
                        )?);

                        (protocol, IPV6_HEADER_SIZE)
                    }
                    _ => {
                        // Unknown EtherType
                        self.offset += PACKET_HEADER_SIZE + cap_len;
                        continue;
                    }
                }
            };

            // Skip if not a UDP packet
            if protocol != PROTOCOL_NUMBER_UDP {
                self.offset += PACKET_HEADER_SIZE + cap_len;
                continue;
            }

            // PCAP Packet Header (16 bytes)
            // Ethernet Header (14 bytes)
            // IP Header (variable)
            // * UDP Header (8 bytes)
            // +---------+--------+-----------+-----------------------------------------+
            // | Indices | Size   | Field     | Description                             |
            // +---------+--------+-----------+-----------------------------------------+
            // | 0..2    | 2      | src_port  | Source Port                             |
            // | 2..4    | 2      | dst_port  | Destination Port                        |
            // | 4..6    | 2      | length    | Total UDP length                        |
            // | 6..8    | 2      | checksum  | Checksum                                |
            // +---------+--------+-----------+-----------------------------------------+
            let dst_port = u16::from_be_bytes(convert_with_offset::<2>(
                self.data,
                self.offset + PACKET_HEADER_SIZE + ETHERNET_HEADER_SIZE + ip_header_size + 2,
            )?);

            // Skip packets not arriving on ports 15515 and 15516
            match dst_port {
                15515..=15516 => (),
                _ => {
                    self.offset += PACKET_HEADER_SIZE + cap_len;
                    continue;
                }
            }

            // PCAP Packet Header (16 bytes)
            // Ethernet Header (14 bytes)
            // IP Header (variable)
            // UDP Header (8 bytes)
            // * Quote Packet
            let payload_start = self.offset
                + PACKET_HEADER_SIZE
                + ETHERNET_HEADER_SIZE
                + ip_header_size
                + UDP_HEADER_SIZE;
            let payload_end = self.offset + PACKET_HEADER_SIZE + cap_len;
            let payload = self.data.get(payload_start..payload_end)?; // Return `None` if not enough data

            // Check if a quote packet
            let result = if payload.starts_with(b"B6034") {
                payload.try_into().ok().map(|data| {
                    let total_usecs: u64 = (ts_sec as u64 * 1_000_000) + (ts_usec as u64);
                    Quote {
                        pkt_time: total_usecs,
                        data,
                    }
                })
            } else {
                None
            };

            // Advance to the next packet
            self.offset += PACKET_HEADER_SIZE + cap_len;

            if result.is_some() {
                return result;
            }
        }

        None
    }
}

#[rustfmt::skip]
fn print_quote(quote: &Quote<'_>) {
    println!(
        concat!(
            "{} {} {} ",
            "{:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} ",
            "{:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5} {:>7}@{:<5}"
        ),
        quote.pkt_time(), quote.accept_time(), quote.issue_code(),
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

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let file = File::open(args.input)?;
    let mmap = unsafe { Mmap::map(&file)? };

    let quote_iterator = QuoteIterator::new(&mmap);

    // 1. Extract the Quote Accept Time (last 8 bytes of message)
    // 2. Push to BinaryHeap for reordering

    // assert_eq!(16004, quote_iterator.count());

    for quote in quote_iterator {
        print_quote(&quote);
    }

    Ok(())
}
