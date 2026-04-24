use smallvec::SmallVec;

use crate::{
    PROTOCOL_NUMBER_UDP, QUOTE_PACKET_SIZE,
    ethernet::EthernetPacket,
    ip::IpPacket,
    pcap::{PcapIterator, PcapPacket},
    time::Timestamp,
    udp::UdpPacket,
};
use std::{collections::BinaryHeap, iter::FusedIterator};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QuotePacket<'a> {
    // Used for "stable" sorting
    pub seq_num: usize,

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

impl<'a> PartialOrd for QuotePacket<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for QuotePacket<'a> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse the comparison for min-heap
        match other.accept_time.cmp(&self.accept_time) {
            std::cmp::Ordering::Equal => {
                // Tie-break with the `seq_num` to prevent unnecessary reordering by the
                // `BinaryHeap`
                other.seq_num.cmp(&self.seq_num)
            }
            order => order,
        }
    }
}

impl<'a> QuotePacket<'a> {
    pub fn new(seq_num: usize, pkt_time: Timestamp, data: &'a [u8]) -> Option<Self> {
        if data.starts_with(b"B6034") {
            let data = data.as_array::<QUOTE_PACKET_SIZE>()?;

            // Number of nanoseconds after midnight
            let day_nanos = Timestamp::hhmmssuu_to_midnight_delta(data[206..214].as_array()?);

            // TODO: `get_midnight_at_timezone` is somewhat slow so if all the packets are from the
            // same day, it could be cached for better performance
            let midnight_at_timezone = pkt_time.get_midnight_at_timezone(Timestamp::TIMEZONE_KST);

            let accept_time = day_nanos + midnight_at_timezone;

            Some(Self {
                seq_num,
                pkt_time,
                accept_time,
                midnight_at_timezone,
                data,
            })
        } else {
            None
        }
    }

    /// Format this quote packet as a fixed-width output line.
    ///
    /// The returned buffer contains the packet fields in text form, including a trailing newline.
    #[inline]
    pub fn to_line_bytes(&'a self) -> [u8; 171] {
        // 170 bytes on the stack shouldn't be a problem
        let mut line_buf = [b' ';
            8 + 1 // pkt-time
            + 8 + 1 // accept-time
            + 12 + 1 // issue-code
            + 10 * (7 + 1 + 5 + 1) // qty(7) + '@'(1) + price(5) + ' '|'\n'(1)
        ];

        line_buf[0..8].copy_from_slice(&self.pkt_time.format_hhmmssuu(self.midnight_at_timezone));
        line_buf[9..17].copy_from_slice(self.accept_time());
        line_buf[18..30].copy_from_slice(self.issue_code());

        macro_rules! write_quantity_and_price {
            ($($start:expr, $quantity:ident, $price:ident);*) => {
                $(
                    // Quantity is 7 bytes
                    line_buf[$start..($start + 7)].copy_from_slice(self.$quantity());
                    // Add the separator
                    line_buf[$start + 7] = b'@';
                    // Prices is 5 bytes
                    line_buf[($start + 8)..($start + 13)].copy_from_slice(self.$price());
                )*
            }
        }

        write_quantity_and_price!(
            31, bid_5_quantity, bid_5_price;
            45, bid_4_quantity, bid_4_price;
            59, bid_3_quantity, bid_3_price;
            73, bid_2_quantity, bid_2_price;
            87, bid_1_quantity, bid_1_price;

            101, ask_1_quantity, ask_1_price;
            115, ask_2_quantity, ask_2_price;
            129, ask_3_quantity, ask_3_price;
            143, ask_4_quantity, ask_4_price;
            157, ask_5_quantity, ask_5_price
        );

        line_buf[170] = b'\n';

        line_buf
    }
}

// Helper macro for reading the fields of the quote packets. This implementation just reads the
// fields as fixed-sized byte arrays.
macro_rules! generate_getters {
    ($($name:ident, $start:expr, $end:expr);*) => {
        impl<'a> QuotePacket<'a> {
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

generate_getters! {
    accept_time, 206, 214;
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
    seq_num: usize,
    pcap_iterator: PcapIterator<'a>,
}

impl<'a> QuoteIterator<'a> {
    pub fn new(pcap_iterator: PcapIterator<'a>) -> Self {
        Self {
            seq_num: 0,
            pcap_iterator,
        }
    }
}

impl<'a> FusedIterator for QuoteIterator<'a> {}

impl<'a> Iterator for QuoteIterator<'a> {
    type Item = QuotePacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        #[inline(always)]
        fn try_map_to_quote<'b>(
            pcap_packet: PcapPacket<'b>,
            seq_num: usize,
        ) -> Option<QuotePacket<'b>> {
            let PcapPacket { pkt_time, data } = pcap_packet;
            let EthernetPacket { ether_type, data } = EthernetPacket::new(data)?;
            let IpPacket { protocol, data } = IpPacket::new(ether_type, data)?;

            // Only accept UDP packets
            if protocol == PROTOCOL_NUMBER_UDP {
                let UdpPacket { dst_port, data } = UdpPacket::new(data)?;

                match dst_port {
                    15515 | 15516 => QuotePacket::new(seq_num, pkt_time, data),
                    _ => None, // Reject packets not on ports 15515 and 15516
                }
            } else {
                None
            }
        }

        for pcap_packet in self.pcap_iterator.by_ref() {
            match try_map_to_quote(pcap_packet, self.seq_num) {
                Some(quote) => {
                    self.seq_num += 1;
                    return Some(quote);
                }
                None => continue,
            }
        }

        None
    }
}

pub struct SortedQuoteIterator<'a> {
    quote_iterator: QuoteIterator<'a>,
    heap: BinaryHeap<QuotePacket<'a>>,
}

impl<'a> SortedQuoteIterator<'a> {
    pub fn new(pcap_iterator: PcapIterator<'a>, init_capacity: usize) -> Self {
        Self {
            quote_iterator: QuoteIterator::new(pcap_iterator),
            heap: BinaryHeap::with_capacity(init_capacity),
        }
    }
}

impl<'a> FusedIterator for SortedQuoteIterator<'a> {}

impl<'a> Iterator for SortedQuoteIterator<'a> {
    type Item = QuotePacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        for quote in self.quote_iterator.by_ref() {
            // Save the latest `pkt_time` before moving the quote to the heap
            let current_time = quote.pkt_time;

            self.heap.push(quote);

            // Return the earliest quote in the heap if it's older than 3 seconds.
            // Note this is "lazy" - it only returns one quote per quote that's pushed in the heap.
            if let Some(earliest) = self.heap.peek()
                && current_time - earliest.accept_time >= Timestamp::from_secs_and_nanos(3, 0)
            {
                let earliest = self.heap.pop().unwrap();
                return Some(earliest);
            }
        }

        if let Some(quote) = self.heap.pop() {
            return Some(quote);
        }

        None
    }
}

#[derive(Debug, Default, Clone)]
struct Bucket<'a> {
    vec: SmallVec<[QuotePacket<'a>; 4]>,
}

// Need at least 300 (3 seconds + centisecond resolution) but use the nearest power of two to make
// modulo calculations faster
const BUCKET_LEN: usize = 512;

pub struct SortedQuoteIterator2<'a> {
    quote_iterator: QuoteIterator<'a>,
    buckets: Box<[Bucket<'a>; BUCKET_LEN]>,
    emit_idx: Option<usize>,
    safe_idx: Option<usize>,
    last_idx: Option<usize>,
}

impl<'a> SortedQuoteIterator2<'a> {
    pub fn new(pcap_iterator: PcapIterator<'a>, _init_capacity: usize) -> Self {
        Self {
            quote_iterator: QuoteIterator::new(pcap_iterator),
            buckets: vec![Default::default(); BUCKET_LEN].try_into().unwrap(),
            emit_idx: None,
            safe_idx: None,
            last_idx: None,
        }
    }
}

impl<'a> FusedIterator for SortedQuoteIterator2<'a> {}

impl<'a> Iterator for SortedQuoteIterator2<'a> {
    type Item = QuotePacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        fn try_emit<'b>(
            emit_idx: &mut usize,
            safe_idx: usize,
            buckets: &mut Box<[Bucket<'b>; BUCKET_LEN]>,
        ) -> Option<QuotePacket<'b>> {
            let (diff, _) = safe_idx.overflowing_sub(*emit_idx);
            let can_emit = diff as isize >= 0;

            if can_emit {
                let mut next_idx = *emit_idx;
                while next_idx != safe_idx {
                    let bucket = buckets.get_mut(next_idx).unwrap();
                    if !bucket.vec.is_empty() {
                        *emit_idx = next_idx;
                        let quote = bucket.vec.remove(0);
                        return Some(quote);
                    }
                    next_idx = (next_idx + 1) % BUCKET_LEN;
                }
            }
            None
        }

        if let Some(emit_idx) = self.emit_idx.as_mut()
            && let Some(safe_idx) = self.safe_idx
            && let Some(quote) = try_emit(emit_idx, safe_idx, &mut self.buckets)
        {
            return Some(quote);
        }

        for quote in self.quote_iterator.by_ref() {
            let current_time = quote.pkt_time;

            let safe_idx = {
                let safe_time = current_time - Timestamp::from_secs_and_nanos(3, 0);
                safe_time.timestamp_centiseconds() as usize % BUCKET_LEN
            };
            self.safe_idx = Some(safe_idx);

            let emit_idx = quote.accept_time.timestamp_centiseconds() as usize % BUCKET_LEN;
            if self.emit_idx.is_none() {
                self.emit_idx = Some(emit_idx);
            }

            self.buckets[emit_idx].vec.push(quote);

            if let Some(emit_idx) = self.emit_idx.as_mut()
                && let Some(safe_idx) = self.safe_idx
                && let Some(quote) = try_emit(emit_idx, safe_idx, &mut self.buckets)
            {
                return Some(quote);
            }
        }

        if self.last_idx.is_none()
            && let Some(emit_idx) = self.emit_idx
        {
            self.last_idx = Some(match emit_idx {
                0 => BUCKET_LEN - 1,
                i => i - 1,
            });
        }

        if let Some(emit_idx) = self.emit_idx.as_mut()
            && let Some(last_idx) = self.last_idx
        {
            let mut next_idx = *emit_idx;
            while next_idx != last_idx {
                let bucket = self.buckets.get_mut(next_idx).unwrap();
                if !bucket.vec.is_empty() {
                    *emit_idx = next_idx;
                    let quote = bucket.vec.remove(0);
                    return Some(quote);
                }
                next_idx = (next_idx + 1) % BUCKET_LEN;
            }
        }

        None
    }
}

#[test]
fn test_quote_parsing() {
    let mmap = crate::open_mmaped_file("../dataset/mdf-kospi200.20110216-0.pcap").unwrap();
    let pcap_iterator = PcapIterator::new(&mmap);
    let quote_iterator = SortedQuoteIterator2::new(pcap_iterator, 3000);

    assert_eq!(quote_iterator.count(), 16004);
}
