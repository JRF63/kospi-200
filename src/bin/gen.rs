//! Generates a PCAP file for benchmarking

use clap::Parser;
use pcap_file::pcap::{PcapPacket, PcapWriter};
use rand_core::SeedableRng;
use rand_distr::{Distribution, Exp};
use rand_xoshiro::Xoshiro256PlusPlus;
use std::{collections::BinaryHeap, fs::File, io::BufWriter, time::Duration};
use tsuru_challenge::{
    ETHERNET_HEADER_SIZE, IPV4_MIN_HEADER_SIZE, QUOTE_PACKET_SIZE, Timestamp, UDP_HEADER_SIZE,
};

const NETWORK_HEADERS_SIZE: usize = ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE + UDP_HEADER_SIZE;
// Valid header taken from mdf-kospi200.20110216-0.pcap
const NETWORK_HEADERS: [u8; NETWORK_HEADERS_SIZE] = [
    1, 0, 94, 37, 54, 61, 0, 18, 68, 200, 56, 10, 8, 0, 69, 0, 0, 243, 231, 179, 0, 0, 59, 17, 181,
    197, 192, 166, 1, 120, 233, 37, 54, 61, 141, 203, 60, 155, 0, 223, 168, 164,
];

const NANOS_PER_SEC: i64 = 1_000_000_000;
const NANOS_PER_HOUR: i64 = 3600 * NANOS_PER_SEC;

const PACKETS_PER_SEC: usize = 750;
const NANOS_PER_PACKET: i64 = NANOS_PER_SEC / PACKETS_PER_SEC as i64;

// From mdf-kospi200.20110216-0.pcap
const START_SECS: i64 = 1297814400;
const START_NANOS: i64 = 6356000;
const START_TIME: i64 = START_SECS * NANOS_PER_SEC + START_NANOS;

// 9 AM
const EXCHANGE_OPENING_TIME: i64 = 9 * NANOS_PER_HOUR;

const THREE_SECONDS: Duration = Duration::from_secs(3);

#[derive(Parser)]
struct Args {
    /// Number of valid quote packets to generate
    num_packets: usize,
}

#[derive(PartialEq, Eq)]
struct DummyQuotePacket {
    timestamp: Duration,
    data: Vec<u8>,
}

// For sorting in order of increasing timestamp
impl Ord for DummyQuotePacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.timestamp.cmp(&self.timestamp)
    }
}

impl PartialOrd for DummyQuotePacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let file = File::create(format!("benchmark-{}.pcap", args.num_packets))?;

    // Default PcapWriter
    let mut writer = PcapWriter::new(BufWriter::new(file))?;

    // Model packet arrival as an exponential distribution with an average delay of 0.5 seconds
    let exp = Exp::new(2.0)?;
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(0xF0F0F0F0F0F0F0F0);

    let mut accept_time = EXCHANGE_OPENING_TIME;

    let mut packets: BinaryHeap<DummyQuotePacket> = BinaryHeap::new();

    // TODO: Maybe generate ARP (0x0806) and raw 802.3
    for counter in 0..(args.num_packets) {
        let mut packet_payload = Vec::with_capacity(NETWORK_HEADERS_SIZE + QUOTE_PACKET_SIZE);
        packet_payload.extend_from_slice(&NETWORK_HEADERS);

        let quote_data = gen_quote(counter, accept_time);
        packet_payload.extend_from_slice(&quote_data);

        // Simulated packet time
        let packet_timestamp = {
            let accept_timestamp =
                Duration::from_nanos((accept_time + (START_TIME - Timestamp::TIMEZONE_KST)) as u64);

            let delay = {
                let delay = Duration::from_secs_f64(exp.sample(&mut rng));

                // Limit to a max of 3 seconds delay
                if delay >= THREE_SECONDS {
                    THREE_SECONDS
                } else {
                    delay
                }
            };

            accept_timestamp + delay
        };

        if let Some(earliest) = packets.peek()
            && packet_timestamp - earliest.timestamp >= THREE_SECONDS
        {
            let DummyQuotePacket { timestamp, data } = packets.pop().unwrap();
            writer.write_packet(&PcapPacket {
                timestamp,
                orig_len: data.len() as u32,
                data: data.into(),
            })?;
        }

        packets.push(DummyQuotePacket {
            timestamp: packet_timestamp,
            data: packet_payload,
        });

        accept_time += NANOS_PER_PACKET;
    }

    while let Some(DummyQuotePacket { timestamp, data }) = packets.pop() {
        writer.write_packet(&PcapPacket {
            timestamp,
            orig_len: data.len() as u32,
            data: data.into(),
        })?;
    }

    Ok(())
}

/// Generates a quote packet. `counter` is written to the issue code for checking the sorting
/// algorithm.
fn gen_quote(counter: usize, accept_time: i64) -> [u8; QUOTE_PACKET_SIZE] {
    let mut out = [0u8; QUOTE_PACKET_SIZE];

    // Fill buffer with ASCII 0
    out.fill(b'0');

    out[..5].copy_from_slice(b"B6034");

    // Issue code
    {
        let isin_code = format!("{:012}", counter);
        out[5..17].copy_from_slice(isin_code.as_bytes());
    }

    // Write accept time
    {
        let day_nanos = Timestamp::from_secs_and_nanos(0, accept_time);
        let hhmmssuu = day_nanos.format_hhmmssuu(Timestamp::from_secs_and_nanos(0, 0));
        out[206..214].copy_from_slice(&hhmmssuu);
    }

    // End of message
    out[214] = 0xFF;

    out
}
