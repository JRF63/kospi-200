use crate::QUOTE_PACKET_SIZE;

#[derive(PartialEq, Eq)]
pub struct QuotePacket<'a> {
    pub seq_num: usize, // Used for "stable" sorting
    pub pkt_time: u64,
    // TODO: add accept time as a u64 for faster comparison
    pub data: &'a [u8; QUOTE_PACKET_SIZE],
}

impl<'a> PartialOrd for QuotePacket<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for QuotePacket<'a> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse the comparison for min-heap
        match other.accept_time().cmp(self.accept_time()) {
            std::cmp::Ordering::Equal => {
                // Tie-break with the `seq_num` to prevent reordering by the `BinaryHeap`
                other.seq_num.cmp(&self.seq_num)
            }
            order => order,
        }
    }
}

impl<'a> QuotePacket<'a> {
    pub fn new(seq_num: usize, ts_sec: u32, ts_usec: u32, data: &'a [u8]) -> Option<Self> {
        if data.starts_with(b"B6034") {
            data.try_into().ok().map(|data| {
                let total_usecs: u64 = (ts_sec as u64 * 1_000_000) + (ts_usec as u64);
                Self {
                    seq_num,
                    pkt_time: total_usecs,
                    data,
                }
            })
        } else {
            None
        }
    }

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

    pub fn pkt_time(&'a self) -> u64 {
        self.pkt_time
    }

    pub fn accept_time(&'a self) -> &'a str {
        self.parse_as_ascii_string::<206, 214>()
    }

    pub fn issue_code(&'a self) -> &'a str {
        self.parse_as_ascii_string::<5, 17>()
    }
}

macro_rules! generate_getters {
    ($($name:ident, $start:expr, $end:expr);*) => {
        impl<'a> QuotePacket<'a> {
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

#[test]
fn test_quote_parsing() {
    use crate::{
        PROTOCOL_NUMBER_UDP,
        ethernet::EthernetPacket,
        ip::IpPacket,
        pcap::{PcapIterator, PcapPacket},
        udp::UdpPacket,
    };

    let mmap = crate::open_mmaped_file("mdf-kospi200.20110216-0.pcap").unwrap();
    let iterator = PcapIterator::new(&mmap);

    assert_eq!(
        iterator
            .enumerate()
            .filter_map(|(seq_num, p)| {
                let PcapPacket {
                    ts_sec,
                    ts_usec,
                    data,
                } = p;
                let EthernetPacket { ether_type, data } = EthernetPacket::new(data)?;
                let IpPacket { protocol, data } = IpPacket::new(ether_type, data)?;

                if protocol == PROTOCOL_NUMBER_UDP {
                    let UdpPacket { dst_port, data } = UdpPacket::new(data)?;
                    match dst_port {
                        15515..=15516 => QuotePacket::new(seq_num, ts_sec, ts_usec, data),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .count(),
        16004
    );
}
