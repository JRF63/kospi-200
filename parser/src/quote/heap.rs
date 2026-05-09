use crate::{
    quote::{Quote, QuotePacket},
    time::Timestamp,
};
use std::{collections::BinaryHeap, iter::FusedIterator};

impl<'a> PartialOrd for Quote<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for Quote<'a> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse the comparison for min-heap
        match other.accept_time.cmp(&self.accept_time) {
            std::cmp::Ordering::Equal => {
                // Tie-break with the `pkt_time` to prevent unnecessary reordering by the
                // `BinaryHeap`
                other.pkt_time.cmp(&self.pkt_time)
            }
            order => order,
        }
    }
}

// O(N*log(N)) sorting
pub struct SortedQuoteIteratorHeap<'a, T> {
    quote_iterator: T,
    heap: BinaryHeap<Quote<'a>>,
}

impl<'a, T> SortedQuoteIteratorHeap<'a, T>
where
    T: Iterator<Item = QuotePacket<'a>>,
{
    pub fn with_capacity(quote_iterator: T, init_capacity: usize) -> Self {
        Self {
            quote_iterator,
            heap: BinaryHeap::with_capacity(init_capacity),
        }
    }
}

impl<'a, T> FusedIterator for SortedQuoteIteratorHeap<'a, T> where
    T: Iterator<Item = QuotePacket<'a>>
{
}

impl<'a, T> Iterator for SortedQuoteIteratorHeap<'a, T>
where
    T: Iterator<Item = QuotePacket<'a>>,
{
    type Item = Quote<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        for quote in self.quote_iterator.by_ref() {
            let current_time = quote.pkt_time;
            self.heap.push(quote.into_quote());

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
