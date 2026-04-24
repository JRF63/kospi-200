use crate::{
    pcap::PcapIterator,
    quote::{QUOTE_PACKET_SIZE, Quote, QuoteIterator},
    time::Timestamp,
};
use std::{collections::BinaryHeap, iter::FusedIterator};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HeapQuotePacket<'a> {
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

impl<'a> PartialOrd for HeapQuotePacket<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for HeapQuotePacket<'a> {
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

impl<'a> From<HeapQuotePacket<'a>> for Quote<'a> {
    fn from(value: HeapQuotePacket<'a>) -> Self {
        let HeapQuotePacket {
            seq_num: _,
            pkt_time,
            accept_time,
            midnight_at_timezone,
            data,
        } = value;
        Self {
            pkt_time,
            accept_time,
            midnight_at_timezone,
            data,
        }
    }
}

// O(N*log(N)) sorting
pub struct SortedQuoteIteratorHeap<'a> {
    quote_iterator: QuoteIterator<'a>,
    heap: BinaryHeap<HeapQuotePacket<'a>>,
    seq_num: usize,
}

impl<'a> SortedQuoteIteratorHeap<'a> {
    pub fn new(pcap_iterator: PcapIterator<'a>, init_capacity: usize) -> Self {
        Self {
            quote_iterator: QuoteIterator::new(pcap_iterator),
            heap: BinaryHeap::with_capacity(init_capacity),
            seq_num: 0,
        }
    }
}

impl<'a> FusedIterator for SortedQuoteIteratorHeap<'a> {}

impl<'a> Iterator for SortedQuoteIteratorHeap<'a> {
    type Item = Quote<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        for quote in self.quote_iterator.by_ref() {
            let current_time = quote.pkt_time;

            let Quote {
                pkt_time,
                accept_time,
                midnight_at_timezone,
                data,
            } = quote.into_quote();

            self.heap.push(HeapQuotePacket {
                seq_num: self.seq_num,
                pkt_time,
                accept_time,
                midnight_at_timezone,
                data,
            });
            self.seq_num += 1;

            // Return the earliest quote in the heap if it's older than 3 seconds.
            // Note this is "lazy" - it only returns one quote per quote that's pushed in the heap.
            if let Some(earliest) = self.heap.peek()
                && current_time - earliest.accept_time >= Timestamp::from_secs_and_nanos(3, 0)
            {
                let earliest = self.heap.pop().unwrap();
                return Some(earliest.into());
            }
        }

        if let Some(quote) = self.heap.pop() {
            return Some(quote.into());
        }

        None
    }
}
