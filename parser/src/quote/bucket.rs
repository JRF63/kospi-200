use crate::{
    pcap::PcapIterator,
    quote::{Quote, QuoteIterator, QuotePacket},
    time::Timestamp,
};
use smallvec::SmallVec;
use std::iter::FusedIterator;

// Need at least 300 (3 seconds + centisecond resolution) but use the nearest power of two to make
// modulo calculations faster
const NUM_BUCKETS: usize = 512;

// Average number of packets per bucket. Try to set this as high as possible while still fitting all
// the buckets within the L1 cache
const BUCKET_SIZE: usize = 4;

// The estimate of the worst case for the number of packets that will be put in a single bucket
const BUCKET_INIT_CAPACITY: usize = 32;

#[derive(Debug, Clone)]
struct Bucket<'a> {
    vec: SmallVec<[QuotePacket<'a>; BUCKET_SIZE]>,

    // These two should all be the same for all quotes inside `vec` above
    accept_time: Timestamp,
    midnight_at_timezone: Timestamp,
}

#[test]
fn test_bucket_mem_size() {
    // Should fit inside L1 cache
    assert!(std::mem::size_of::<Bucket<'_>>() * NUM_BUCKETS < 64_000);
}

impl<'a> Bucket<'a> {
    fn new_empty_bucket() -> Self {
        const EPOCH: Timestamp = Timestamp::from_secs_and_nanos(0, 0);
        Self {
            vec: SmallVec::with_capacity(BUCKET_INIT_CAPACITY),
            accept_time: EPOCH,
            midnight_at_timezone: EPOCH,
        }
    }

    fn remove(&mut self, index: usize) -> Quote<'a> {
        let QuotePacket { pkt_time, data } = self.vec.remove(index);

        Quote {
            pkt_time,
            accept_time: self.accept_time,
            midnight_at_timezone: self.midnight_at_timezone,
            data,
        }
    }
    fn push(
        &mut self,
        quote: QuotePacket<'a>,
        accept_time: Timestamp,
        midnight_at_timezone: Timestamp,
    ) {
        self.accept_time = accept_time;
        self.midnight_at_timezone = midnight_at_timezone;

        self.vec.push(quote);
    }

    fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }
}

// Bucket sorting - O(N)
pub struct SortedQuoteIteratorBuckets<'a> {
    quote_iterator: QuoteIterator<'a>,
    buckets: Box<[Bucket<'a>; NUM_BUCKETS]>,
    earliest_accept_time: Timestamp,

    // Tried to use a `usize` for these indices with `NUM_BUCKETS` as a sentinel but that resulted
    // in 2% worse performance
    emit_idx: Option<usize>,
    safe_idx: Option<usize>,
    last_idx: Option<usize>,
}

impl<'a> SortedQuoteIteratorBuckets<'a> {
    pub fn new(pcap_iterator: PcapIterator<'a>) -> Self {
        Self {
            quote_iterator: QuoteIterator::new(pcap_iterator),

            // This might create a temporary value on the stack
            buckets: Box::new(std::array::from_fn(|_| Bucket::new_empty_bucket())),

            earliest_accept_time: Timestamp::from_secs_and_nanos(0, i64::MAX),
            emit_idx: None,
            safe_idx: None,
            last_idx: None,
        }
    }

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

            if !bucket.is_empty() {
                *emit_idx = next_idx;

                // This is O(N) so must keep the size of the buckets small
                let quote = bucket.remove(0);

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

impl<'a> FusedIterator for SortedQuoteIteratorBuckets<'a> {}

impl<'a> Iterator for SortedQuoteIteratorBuckets<'a> {
    type Item = Quote<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Greedily try to emit a packet. This prevents the `SmallVec`s from allocating by keeping
        // them small.
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
