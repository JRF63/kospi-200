use crate::QUOTE_PACKET_SIZE;
use chrono::{DateTime, Timelike};

#[derive(PartialEq, Eq)]
pub struct QuotePacket<'a> {
    pub seq_num: usize, // Used for "stable" sorting
    pub pkt_time: i64,
    pub accept_time: i64,
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
                // Tie-break with the `seq_num` to prevent reordering by the `BinaryHeap`
                other.seq_num.cmp(&self.seq_num)
            }
            order => order,
        }
    }
}

fn calculate_accept_time_micros(hour: u64, min: u64, sec: u64, cent: u64) -> u64 {
    const HOUR_MICROS: u64 = 3_600_000_000;
    const MIN_MICROS: u64 = 60_000_000;
    const SEC_MICROS: u64 = 1_000_000;
    const CENT_MICROS: u64 = 10_000;

    hour * HOUR_MICROS + min * MIN_MICROS + sec * SEC_MICROS + cent * CENT_MICROS
}

fn parse_accept_time(data: &[u8; QUOTE_PACKET_SIZE]) -> [u64; 4] {
    // SAFETY: 206..214 is exactly 8 bytes
    let bytes: [u8; 8] = unsafe { *data[206..214].as_array().unwrap_unchecked() };

    let val = u64::from_le_bytes(bytes);

    // Subtract ASCII '0' from all 8 bytes simultaneously
    let digits = val - 0x3030303030303030;

    let hour = (digits & 0xFF) * 10 + ((digits >> 8) & 0xFF);
    let min = ((digits >> 16) & 0xFF) * 10 + ((digits >> 24) & 0xFF);
    let sec = ((digits >> 32) & 0xFF) * 10 + ((digits >> 40) & 0xFF);
    let cent = ((digits >> 48) & 0xFF) * 10 + ((digits >> 56) & 0xFF);

    [hour, min, sec, cent]
}

impl<'a> QuotePacket<'a> {
    pub fn new(
        seq_num: usize,
        pkt_time: i64,
        data: &'a [u8],
        base_timestamp: &mut Option<i64>,
    ) -> Option<Self> {
        if data.starts_with(b"B6034") {
            let data = data.as_array::<QUOTE_PACKET_SIZE>()?;

            let [hour, min, sec, cent] = parse_accept_time(data);
            let micros_after_midnight = calculate_accept_time_micros(hour, min, sec, cent) as i64;

            // Avoid using `chrono::DateTime` as much as possible
            let accept_time = match base_timestamp {
                Some(delta) => {
                    // The fast path
                    *delta + micros_after_midnight
                }
                None => {
                    let pkt_time_dt = DateTime::from_timestamp_micros(pkt_time)?;

                    // This part is relatively slow
                    let accept_time_dt = pkt_time_dt
                        .with_hour(hour as u32)?
                        .with_minute(min as u32)?
                        .with_second(sec as u32)?
                        .with_nanosecond(cent as u32 * 10_000_000)?;

                    let accept_time = accept_time_dt.timestamp_micros();

                    // Pre-calculate a timestamp offset on the first packet so we only have to do
                    // the expensive DateTime calculation once
                    *base_timestamp = Some(accept_time - micros_after_midnight);
                    accept_time
                }
            };

            Some(Self {
                seq_num,
                pkt_time,
                accept_time,
                data,
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

    pub fn pkt_time(&'a self) -> i64 {
        self.pkt_time
    }

    pub fn accept_time_str(&'a self) -> &'a str {
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
    use crate::{build_quote_iterator, pcap::PcapIterator};

    let mmap = crate::open_mmaped_file("mdf-kospi200.20110216-0.pcap").unwrap();

    let mut base_timestamp: Option<i64> = None;
    let quote_iterator = build_quote_iterator(PcapIterator::new(&mmap), &mut base_timestamp);

    assert_eq!(quote_iterator.count(), 16004);
}
