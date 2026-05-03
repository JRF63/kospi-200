use crate::{
    quote::{Quote, QuotePacket},
    time::Timestamp,
};
use std::{collections::VecDeque, iter::FusedIterator};

// Need at least 300 (3 seconds + centisecond resolution) but use the nearest power of two to make
// modulo calculations faster
const NUM_BUCKETS: usize = 512;

const EPOCH: Timestamp = Timestamp::from_secs_and_nanos(0, 0);

#[derive(Debug, Clone)]
struct Bucket<'a> {
    deque: VecDeque<QuotePacket<'a>>,

    // These two should all be the same for all quotes inside `vec` above
    accept_time: Timestamp,
    midnight_at_timezone: Timestamp,
}

impl<'a> Bucket<'a> {
    fn with_capacity(bucket_capacity: usize) -> Self {
        Self {
            deque: VecDeque::with_capacity(bucket_capacity),
            accept_time: EPOCH,
            midnight_at_timezone: EPOCH,
        }
    }

    fn pop(&mut self) -> Option<Quote<'a>> {
        self.deque.pop_back().map(|p| {
            let QuotePacket { pkt_time, data } = p;
            Quote {
                pkt_time,
                accept_time: self.accept_time,
                midnight_at_timezone: self.midnight_at_timezone,
                data,
            }
        })
    }

    fn push(
        &mut self,
        quote: QuotePacket<'a>,
        accept_time: Timestamp,
        midnight_at_timezone: Timestamp,
    ) {
        self.accept_time = accept_time;
        self.midnight_at_timezone = midnight_at_timezone;

        // Insert to the front to maintain a stable sort
        self.deque.push_front(quote);
    }
}

// Bucket sorting - O(N)
pub struct SortedQuoteIteratorBuckets<'a, T> {
    quote_iterator: T,
    buckets: [Bucket<'a>; NUM_BUCKETS],
    earliest_accept_time: Timestamp,

    // Tried to use a `usize` for these indices with `NUM_BUCKETS` as a sentinel but that resulted
    // in 2% worse performance
    emit_idx: Option<usize>,
    safe_idx: Option<usize>,
    last_idx: Option<usize>,
}

impl<'a, T> SortedQuoteIteratorBuckets<'a, T>
where
    T: Iterator<Item = QuotePacket<'a>>,
{
    pub fn with_capacity(quote_iterator: T, bucket_capacity: usize) -> Self {
        Self {
            quote_iterator,
            buckets: std::array::from_fn(|_| Bucket::with_capacity(bucket_capacity)),
            earliest_accept_time: Timestamp::from_secs_and_nanos(0, i64::MAX),
            emit_idx: None,
            safe_idx: None,
            last_idx: None,
        }
    }
}

impl<'a, T> SortedQuoteIteratorBuckets<'a, T> {
    // Try to return one packet from the buckets
    fn try_emit_packet<'b>(
        emit_idx: &mut usize,
        safe_idx: usize,
        buckets: &mut [Bucket<'b>; NUM_BUCKETS],
    ) -> Option<Quote<'b>> {
        let mut next_idx = *emit_idx;
        loop {
            // SAFETY: `emit_idx` should be < `NUM_BUCKETS`, `next_idx` is also clamped to
            // `0..NUM_BUCKETS` when incremented
            let bucket = unsafe { buckets.get_unchecked_mut(next_idx) };

            if let Some(quote) = bucket.pop() {
                *emit_idx = next_idx;
                return Some(quote);
            }

            if next_idx == safe_idx {
                break;
            }
            next_idx = (next_idx + 1) % NUM_BUCKETS;
        }
        None
    }

    // Return a packet older than 3 seconds
    fn try_emit_elapsed_packet<'b>(
        emit_idx: &mut Option<usize>,
        safe_idx: Option<usize>,
        buckets: &mut [Bucket<'b>; NUM_BUCKETS],
    ) -> Option<Quote<'b>> {
        if let Some(emit_idx) = emit_idx.as_mut()
            && let Some(safe_idx) = safe_idx
        {
            // Check if `safe_idx` >= `emit_idx` using the half-range rule
            let gt_or_eq = {
                let diff = safe_idx.wrapping_sub(*emit_idx) % NUM_BUCKETS;

                // diff >= 0 && diff <= mid
                (0..=(NUM_BUCKETS / 2)).contains(&diff)
            };

            if gt_or_eq && let Some(quote) = Self::try_emit_packet(emit_idx, safe_idx, buckets) {
                return Some(quote);
            }
        }

        None
    }
}

impl<'a, T> FusedIterator for SortedQuoteIteratorBuckets<'a, T> where
    T: Iterator<Item = QuotePacket<'a>>
{
}

impl<'a, T> Iterator for SortedQuoteIteratorBuckets<'a, T>
where
    T: Iterator<Item = QuotePacket<'a>>,
{
    type Item = Quote<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Greedily try to emit a packet. This keeps the bucket small.
        if let Some(quote) =
            Self::try_emit_elapsed_packet(&mut self.emit_idx, self.safe_idx, &mut self.buckets)
        {
            return Some(quote);
        }

        const THREE_SECONDS: Timestamp = Timestamp::from_secs_and_nanos(3, 0);

        for quote in self.quote_iterator.by_ref() {
            // TODO: Try leaving calcs in centiseconds
            let Quote {
                pkt_time,
                accept_time,
                midnight_at_timezone,
                data,
            } = quote.into_quote();

            let safe_idx = {
                let safe_time = pkt_time - THREE_SECONDS;
                safe_time.timestamp_centiseconds() as usize % NUM_BUCKETS
            };
            self.safe_idx = Some(safe_idx);

            let idx = accept_time.timestamp_centiseconds() as usize % NUM_BUCKETS;

            // Initialize the index of the bucket that will be emitted first
            if self.emit_idx.is_none() {
                if accept_time < self.earliest_accept_time {
                    self.earliest_accept_time = accept_time;
                }

                if pkt_time - self.earliest_accept_time >= THREE_SECONDS {
                    let emit_idx =
                        self.earliest_accept_time.timestamp_centiseconds() as usize % NUM_BUCKETS;
                    self.emit_idx = Some(emit_idx);
                }
            }

            self.buckets[idx].push(
                QuotePacket { pkt_time, data },
                accept_time,
                midnight_at_timezone,
            );

            if let Some(quote) =
                Self::try_emit_elapsed_packet(&mut self.emit_idx, self.safe_idx, &mut self.buckets)
            {
                return Some(quote);
            }
        }

        // Drain the rest of the packets from the buckets
        if let Some(emit_idx) = self.emit_idx.as_mut() {
            match self.last_idx {
                Some(last_idx) => {
                    if let Some(quote) =
                        Self::try_emit_packet(emit_idx, last_idx, &mut self.buckets)
                    {
                        return Some(quote);
                    }
                }
                None => {
                    let last_idx = match *emit_idx {
                        0 => NUM_BUCKETS - 1,
                        i => i - 1,
                    };
                    self.last_idx = Some(last_idx);
                    if let Some(quote) =
                        Self::try_emit_packet(emit_idx, last_idx, &mut self.buckets)
                    {
                        return Some(quote);
                    }
                }
            }
        }

        None
    }
}
