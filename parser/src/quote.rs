mod bucket;
mod heap;

pub use self::{bucket::SortedQuoteIteratorBuckets, heap::SortedQuoteIteratorHeap};
use crate::{
    PROTOCOL_NUMBER_UDP, QUOTE_PACKET_SIZE,
    ethernet::EthernetPacket,
    ip::IpPacket,
    pcap::{PcapIterator, PcapPacket},
    time::Timestamp,
    udp::UdpPacket,
};
use std::iter::FusedIterator;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QuotePacket<'a> {
    // Packet reception time (UTC)
    pub pkt_time: Timestamp,

    // Payload
    pub data: &'a [u8; QUOTE_PACKET_SIZE],
}

impl<'a> QuotePacket<'a> {
    pub fn new(pkt_time: Timestamp, data: &'a [u8]) -> Option<Self> {
        if data.starts_with(b"B6034") {
            Some(Self {
                pkt_time,
                data: data.as_array::<QUOTE_PACKET_SIZE>()?,
            })
        } else {
            None
        }
    }

    pub fn into_quote(self) -> Quote<'a> {
        self.into()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Quote<'a> {
    // Packet reception time (UTC)
    pub pkt_time: Timestamp,

    // Accept time at the exchange (UTC)
    // Both timestamps need to have the same TZ for fast comparison
    pub accept_time: Timestamp,

    // Midnight of the day that the packet was accepted at the exchange
    pub midnight_at_timezone: Timestamp,

    // Payload
    pub data: &'a [u8; QUOTE_PACKET_SIZE],
}

impl<'a> From<QuotePacket<'a>> for Quote<'a> {
    fn from(value: QuotePacket<'a>) -> Self {
        let QuotePacket { pkt_time, data } = value;

        // Number of nanoseconds after midnight
        let day_nanos = Timestamp::hhmmssuu_to_midnight_delta(data[206..214].as_array().unwrap());

        // NOTE: This is somewhat slow but caching it yields negligible performance
        let midnight_at_timezone = pkt_time.get_midnight_at_timezone(Timestamp::TIMEZONE_KST);

        let accept_time = day_nanos + midnight_at_timezone;

        Self {
            pkt_time,
            accept_time,
            midnight_at_timezone,
            data,
        }
    }
}

impl<'a> Quote<'a> {
    /// Format this quote as a fixed-width output line.
    ///
    /// The returned buffer contains the fields in text form, including a trailing newline.
    #[inline]
    pub fn to_line_bytes(&'a self) -> [u8; 185] {
        // Removes leading ASCII zeros and right aligns the quantity@price string
        fn write_quantity_price_pair(out: &mut [u8; 13], quantity: &[u8; 7], price: &[u8; 5]) {
            macro_rules! write_pair {
                ($leading_zeros:expr, $quantity_len:expr, $q:expr, $p:expr) => {
                    out[$leading_zeros..($leading_zeros + $quantity_len)].copy_from_slice($q);
                    out[$leading_zeros + $quantity_len] = b'@';
                    out[($leading_zeros + $quantity_len + 1)..].copy_from_slice($p);
                };
            }

            macro_rules! gen_price_match_arms {
                ($quantity_len:expr, $q:expr) => {
                    match price {
                        [b'0', b'0', b'0', b'0', b'0'] => {
                            write_pair!(7 + 4 - $quantity_len, $quantity_len, $q, b"0");
                        }
                        [b'0', b'0', b'0', b'0', p @ ..] => {
                            write_pair!(7 + 4 - $quantity_len, $quantity_len, $q, p);
                        }
                        [b'0', b'0', b'0', p @ ..] => {
                            write_pair!(7 + 3 - $quantity_len, $quantity_len, $q, p);
                        }
                        [b'0', b'0', p @ ..] => {
                            write_pair!(7 + 2 - $quantity_len, $quantity_len, $q, p);
                        }
                        [b'0', p @ ..] => {
                            write_pair!(7 + 1 - $quantity_len, $quantity_len, $q, p);
                        }
                        p => {
                            write_pair!(7 - $quantity_len, $quantity_len, $q, p);
                        }
                    }
                };
            }

            match quantity {
                [b'0', b'0', b'0', b'0', b'0', b'0', b'0'] => gen_price_match_arms!(1, b"0"),
                [b'0', b'0', b'0', b'0', b'0', b'0', q @ ..] => gen_price_match_arms!(1, q),
                [b'0', b'0', b'0', b'0', b'0', q @ ..] => gen_price_match_arms!(2, q),
                [b'0', b'0', b'0', b'0', q @ ..] => gen_price_match_arms!(3, q),
                [b'0', b'0', b'0', q @ ..] => gen_price_match_arms!(4, q),
                [b'0', b'0', q @ ..] => gen_price_match_arms!(5, q),
                [b'0', q @ ..] => gen_price_match_arms!(6, q),
                q => gen_price_match_arms!(7, q),
            }
        }

        self.to_line_bytes_base(write_quantity_price_pair)
    }

    // Used for benchmarking. Skips the slow removing of leading zeros.
    pub fn to_line_bytes_fast(&'a self) -> [u8; 185] {
        fn write_quantity_price_pair(out: &mut [u8; 13], quantity: &[u8; 7], price: &[u8; 5]) {
            out[..7].copy_from_slice(quantity);
            out[7] = b'@';
            out[8..].copy_from_slice(price);
        }
        self.to_line_bytes_base(write_quantity_price_pair)
    }

    // The `write_quantity_price_pair` is for formatting the quantity@price string
    fn to_line_bytes_base<F>(&'a self, write_quantity_price_pair: F) -> [u8; 185]
    where
        F: Fn(&mut [u8; 13], &[u8; 7], &[u8; 5]),
    {
        // 185 bytes on the stack shouldn't be a problem
        let mut line_buf = [b' ';
            15 + 1 // pkt-time
            + 15 + 1 // accept-time
            + 12 + 1 // issue-code
            + 10 * (7 + 1 + 5 + 1) // qty(7) + '@'(1) + price(5) + ' '|'\n'(1)
        ];

        // Time formatting could be a parameter too if it doesn't affect the offsets
        let midnight = self.midnight_at_timezone;
        line_buf[0..15].copy_from_slice(&self.pkt_time.as_printable_time_string(midnight));
        line_buf[16..31].copy_from_slice(&self.accept_time.as_printable_time_string(midnight));

        line_buf[32..44].copy_from_slice(self.issue_code());

        macro_rules! write_quantity_and_price {
            ($($start:expr, $quantity:ident, $price:ident);*) => {
                $(
                    write_quantity_price_pair(
                        line_buf[$start..($start + 13)].as_mut_array().unwrap(),
                        self.$quantity(),
                        self.$price(),
                    );
                )*
            }
        }

        write_quantity_and_price!(
            45, bid_5_quantity, bid_5_price;
            59, bid_4_quantity, bid_4_price;
            73, bid_3_quantity, bid_3_price;
            87, bid_2_quantity, bid_2_price;
            101, bid_1_quantity, bid_1_price;

            115, ask_1_quantity, ask_1_price;
            129, ask_2_quantity, ask_2_price;
            143, ask_3_quantity, ask_3_price;
            157, ask_4_quantity, ask_4_price;
            171, ask_5_quantity, ask_5_price
        );

        line_buf[184] = b'\n';

        line_buf
    }
}

// Helper macro for reading the fields of the quote packets. This implementation just reads the
// fields as fixed-sized byte arrays.
macro_rules! generate_getters {
    ($($name:ident, $start:expr, $end:expr);*) => {
        impl<'a> Quote<'a> {
            $(
                // Use fixed sized arrays for bounds check elision
                fn $name(&'a self) -> &'a [u8; $end - $start] {
                    // SAFETY: The enclosing macro ensures the length is correct
                    unsafe { self.data[$start..$end].as_array().unwrap_unchecked() }
                }
            )*
        }
    }
}

// +----------+------+------------------------------------+
// | Indices  | Size | Field                              |
// +----------+------+------------------------------------+
// | 0..2     | 2    | Data Type (B6)                     |
// | 2..4     | 2    | Information Type (03)              |
// | 4..5     | 1    | Market Type (4)                    |
// | 5..17    | 12   | Issue code                         |
// | 17..20   | 3    | Issue seq.-no.                     |
// | 20..22   | 2    | Market Status Type                 |
// | 22..29   | 7    | Total bid quote volume             |
// | 29..34   | 5    | Best bid price(1st) (ASCII)        |
// | 34..41   | 7    | Best bid quantity(1st) (ASCII)     |
// | 41..46   | 5    | Best bid price(2nd)                |
// | 46..53   | 7    | Best bid quantity(2nd)             |
// | 53..58   | 5    | Best bid price(3rd)                |
// | 58..65   | 7    | Best bid quantity(3rd)             |
// | 65..70   | 5    | Best bid price(4th)                |
// | 70..77   | 7    | Best bid quantity(4th)             |
// | 77..82   | 5    | Best bid price(5th)                |
// | 82..89   | 7    | Best bid quantity(5th)             |
// | 89..96   | 7    | Total ask quote volume             |
// | 96..101  | 5    | Best ask price(1st)                |
// | 101..108 | 7    | Best ask quantity(1st)             |
// | 108..113 | 5    | Best ask price(2nd)                |
// | 113..120 | 7    | Best ask quantity(2nd)             |
// | 120..125 | 5    | Best ask price(3rd)                |
// | 125..132 | 7    | Best ask quantity(3rd)             |
// | 132..137 | 5    | Best ask price(4th)                |
// | 137..144 | 7    | Best ask quantity(4th)             |
// | 144..149 | 5    | Best ask price(5th)                |
// | 149..156 | 7    | Best ask quantity(5th)             |
// | 156..161 | 5    | No. of best bid valid quote(total) |
// | 161..165 | 4    | No. of best bid quote(1st)         |
// | 165..169 | 4    | No. of best bid quote(2nd)         |
// | 169..173 | 4    | No. of best bid quote(3rd)         |
// | 173..177 | 4    | No. of best bid quote(4th)         |
// | 177..181 | 4    | No. of best bid quote(5th)         |
// | 181..186 | 5    | No. of best ask valid quote(total) |
// | 186..190 | 4    | No. of best ask quote(1st)         |
// | 190..194 | 4    | No. of best ask quote(2nd)         |
// | 194..198 | 4    | No. of best ask quote(3rd)         |
// | 198..202 | 4    | No. of best ask quote(4th)         |
// | 202..206 | 4    | No. of best ask quote(5th)         |
// | 206..214 | 8    | Quote accept time (HHMMSSuu)       |
// | 214..215 | 1    | End of Message (0xF)               |
// +----------+------+------------------------------------+
generate_getters! {
    issue_code, 5, 17;

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

pub struct QuoteIterator<'a> {
    pcap_iterator: PcapIterator<'a>,
}

impl<'a> QuoteIterator<'a> {
    pub fn new(pcap_iterator: PcapIterator<'a>) -> Self {
        Self { pcap_iterator }
    }
}

impl<'a> FusedIterator for QuoteIterator<'a> {}

impl<'a> Iterator for QuoteIterator<'a> {
    type Item = QuotePacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        #[inline(always)]
        fn try_map_to_quote<'b>(pcap_packet: PcapPacket<'b>) -> Option<QuotePacket<'b>> {
            let PcapPacket { pkt_time, data } = pcap_packet;
            let EthernetPacket { ether_type, data } = EthernetPacket::new(data)?;
            let IpPacket { protocol, data } = IpPacket::new(ether_type, data)?;

            // Only accept UDP packets
            if protocol == PROTOCOL_NUMBER_UDP {
                let UdpPacket { dst_port, data } = UdpPacket::new(data)?;

                match dst_port {
                    15515 | 15516 => QuotePacket::new(pkt_time, data),
                    _ => None, // Reject packets not on ports 15515 and 15516
                }
            } else {
                None
            }
        }

        for pcap_packet in self.pcap_iterator.by_ref() {
            match try_map_to_quote(pcap_packet) {
                Some(quote) => return Some(quote),
                None => continue,
            }
        }

        None
    }
}

#[test]
fn test_quote_parsing() {
    let filename = "../dataset/mdf-kospi200.20110216-0.pcap";

    let count_a = {
        let mmap = crate::open_mmaped_file(filename).unwrap();
        let pcap_iterator = PcapIterator::new(&mmap);
        let quote_iterator = QuoteIterator::new(pcap_iterator);
        quote_iterator.count()
    };

    let count_b = {
        let mmap = crate::open_mmaped_file(filename).unwrap();
        let pcap_iterator = PcapIterator::new(&mmap);
        let quote_iterator =
            SortedQuoteIteratorHeap::with_capacity(QuoteIterator::new(pcap_iterator), 3000);
        quote_iterator.count()
    };

    let count_c = {
        let mmap = crate::open_mmaped_file(filename).unwrap();
        let pcap_iterator = PcapIterator::new(&mmap);
        let quote_iterator =
            SortedQuoteIteratorBuckets::with_capacity(QuoteIterator::new(pcap_iterator), 32);
        quote_iterator.count()
    };

    assert_eq!(count_a, 16004);
    assert_eq!(count_b, 16004);
    assert_eq!(count_c, 16004);
}

#[test]
fn test_quote_sorting() {
    let filename = "../dataset/mdf-kospi200.20110216-0.pcap";

    let mmap = crate::open_mmaped_file(filename).unwrap();
    let quote_iterator_a = {
        let pcap_iterator = PcapIterator::new(&mmap);
        SortedQuoteIteratorHeap::with_capacity(QuoteIterator::new(pcap_iterator), 3000)
    };

    let mmap = crate::open_mmaped_file(filename).unwrap();
    let quote_iterator_b = {
        let pcap_iterator = PcapIterator::new(&mmap);
        SortedQuoteIteratorBuckets::with_capacity(QuoteIterator::new(pcap_iterator), 32)
    };

    let mut accept_time_a = Timestamp::from_secs_and_nanos(0, 0);
    let mut accept_time_b = Timestamp::from_secs_and_nanos(0, 0);

    for (a, b) in quote_iterator_a.zip(quote_iterator_b) {
        // Test if accept times are monotonically increasing
        assert!(accept_time_a <= a.accept_time);
        accept_time_a = a.accept_time;

        assert!(accept_time_b <= b.accept_time);
        accept_time_b = b.accept_time;

        assert_eq!(a, b);
    }
}

#[test]
fn test_bucket_sort_corner_case() {
    const NANOS_PER_CENT: i64 = 10000000;
    const THREE_SECONDS: Timestamp = Timestamp::from_secs_and_nanos(3, 0);

    const START: Timestamp = Timestamp::from_secs_and_nanos(1297814400, 0);
    const MIDNIGHT: Timestamp = START.get_midnight_at_timezone(Timestamp::TIMEZONE_KST);

    // (data, accept_time, pkt_time)
    let mut packet_data = [
        (
            vec![b'0'; QUOTE_PACKET_SIZE],
            START + Timestamp::from_secs_and_nanos(0, 0),
            START + Timestamp::from_secs_and_nanos(0, 5 * NANOS_PER_CENT),
        ),
        (
            vec![b'0'; QUOTE_PACKET_SIZE],
            START + Timestamp::from_secs_and_nanos(0, 10 * NANOS_PER_CENT),
            START + Timestamp::from_secs_and_nanos(0, 15 * NANOS_PER_CENT),
        ),
        (
            vec![b'0'; QUOTE_PACKET_SIZE],
            START + Timestamp::from_secs_and_nanos(0, 20 * NANOS_PER_CENT),
            START + Timestamp::from_secs_and_nanos(0, 25 * NANOS_PER_CENT),
        ),
        (
            vec![b'0'; QUOTE_PACKET_SIZE],
            START + Timestamp::from_secs_and_nanos(0, 512 * NANOS_PER_CENT),
            START + Timestamp::from_secs_and_nanos(0, 517 * NANOS_PER_CENT),
        ),
        (
            vec![b'0'; QUOTE_PACKET_SIZE],
            START + Timestamp::from_secs_and_nanos(0, 522 * NANOS_PER_CENT),
            START + Timestamp::from_secs_and_nanos(0, 527 * NANOS_PER_CENT),
        ),
        (
            vec![b'0'; QUOTE_PACKET_SIZE],
            START + Timestamp::from_secs_and_nanos(0, 532 * NANOS_PER_CENT),
            START + Timestamp::from_secs_and_nanos(0, 537 * NANOS_PER_CENT),
        ),
    ];

    let packets = packet_data.each_mut().map(|(data, accept_time, pkt_time)| {
        data[206..214].copy_from_slice(&accept_time.as_hhmmssuu_string(MIDNIGHT));
        QuotePacket {
            pkt_time: *pkt_time,
            data: data.as_slice().try_into().unwrap(),
        }
    });

    for (i, p) in packets.iter().enumerate() {
        let Quote { accept_time, .. } = p.clone().into_quote();
        assert!(
            p.pkt_time - accept_time <= THREE_SECONDS,
            "{}: {:?}",
            i,
            p.pkt_time - accept_time
        );
    }

    let quote_iterator_a = SortedQuoteIteratorHeap::with_capacity(packets.iter().cloned(), 10);
    let quote_iterator_b = SortedQuoteIteratorBuckets::with_capacity(packets.iter().cloned(), 32);

    let mut accept_time_a = Timestamp::from_secs_and_nanos(0, 0);
    let mut accept_time_b = Timestamp::from_secs_and_nanos(0, 0);

    for (a, b) in quote_iterator_a.zip(quote_iterator_b) {
        // Test if accept times are monotonically increasing
        assert!(accept_time_a <= a.accept_time);
        accept_time_a = a.accept_time;

        assert!(accept_time_b <= b.accept_time);
        accept_time_b = b.accept_time;

        assert_eq!(a, b);
    }
}
