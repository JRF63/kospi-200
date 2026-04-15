use crate::{QUOTE_PACKET_SIZE, time::Timestamp};
use std::io::{BufWriter, Write};

#[derive(PartialEq, Eq)]
pub struct QuotePacket<'a> {
    // Used for "stable" sorting
    pub seq_num: usize,

    // Packet reception time (UTC)
    pub pkt_time: Timestamp,

    // Accept time at the exchange (UTC)
    // Both timestamps need to have the same TZ for fast comparison
    pub accept_time: Timestamp,

    // UTC timestamp of midnight based on `pkt_time` above
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

/// Optimized parsing of HHMMSSuu
fn parse_accept_time(data: &[u8; QUOTE_PACKET_SIZE]) -> [u64; 4] {
    let bytes: [u8; 8] = *data[206..214].as_array().unwrap();

    let val = u64::from_le_bytes(bytes);

    // Subtract ASCII '0' from all 8 bytes
    let digits = val - 0x3030303030303030;

    let hour = (digits & 0xFF) * 10 + ((digits >> 8) & 0xFF);
    let min = ((digits >> 16) & 0xFF) * 10 + ((digits >> 24) & 0xFF);
    let sec = ((digits >> 32) & 0xFF) * 10 + ((digits >> 40) & 0xFF);
    let cent = ((digits >> 48) & 0xFF) * 10 + ((digits >> 56) & 0xFF);

    [hour, min, sec, cent]
}

impl<'a> QuotePacket<'a> {
    pub fn new(seq_num: usize, pkt_time: Timestamp, data: &'a [u8]) -> Option<Self> {
        if data.starts_with(b"B6034") {
            let data = data.as_array::<QUOTE_PACKET_SIZE>()?;

            let [hour, min, sec, cent] = parse_accept_time(data);

            // Number of nanoseconds after midnight
            let day_nanos = Timestamp::delta_time_after_midnight(hour, min, sec, cent);

            // TODO: `get_midnight_at_timezone` is somewhat slow so if all the packets are from the
            // same day, it could be cached for better performance
            let midnight_at_timezone =
                pkt_time.get_midnight_at_timezone::<{ Timestamp::TIMEZONE_OFFSET }>();

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

    pub fn write_line(
        &'a self,
        writer: &mut BufWriter<std::io::StdoutLock>,
    ) -> std::io::Result<()> {
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

        writer.write_all(&line_buf)?;

        Ok(())
    }
}

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

#[test]
fn test_parse_accept_time() {
    let mut data = [0; QUOTE_PACKET_SIZE];
    data[206..214].copy_from_slice(b"12304580");
    let [hour, min, sec, cent] = parse_accept_time(&data);

    assert_eq!(hour, 12);
    assert_eq!(min, 30);
    assert_eq!(sec, 45);
    assert_eq!(cent, 80);
}

#[test]
fn test_quote_parsing() {
    use crate::{build_quote_iterator, pcap::PcapIterator};

    let mmap = crate::open_mmaped_file("mdf-kospi200.20110216-0.pcap").unwrap();

    let quote_iterator = build_quote_iterator(PcapIterator::new(&mmap));

    assert_eq!(quote_iterator.count(), 16004);
}
