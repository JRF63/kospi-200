use crate::{
    pcap::PcapIterator,
    quote::{QuoteIterator, QuotePacket},
    time::Timestamp,
};
use std::{collections::BinaryHeap, iter::FusedIterator};

// O(N*log(N)) sorting
pub struct SortedQuoteIteratorHeap<'a> {
    quote_iterator: QuoteIterator<'a>,
    heap: BinaryHeap<QuotePacket<'a>>,
}

impl<'a> SortedQuoteIteratorHeap<'a> {
    pub fn new(pcap_iterator: PcapIterator<'a>, init_capacity: usize) -> Self {
        Self {
            quote_iterator: QuoteIterator::new(pcap_iterator),
            heap: BinaryHeap::with_capacity(init_capacity),
        }
    }
}

impl<'a> FusedIterator for SortedQuoteIteratorHeap<'a> {}

impl<'a> Iterator for SortedQuoteIteratorHeap<'a> {
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
