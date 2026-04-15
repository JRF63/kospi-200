const NANOS_PER_HOUR: i64 = 3600 * NANOS_PER_SEC;
const NANOS_PER_MIN: i64 = 60 * NANOS_PER_SEC;
const NANOS_PER_SEC: i64 = 1_000_000_000;
const NANOS_PER_CENT: i64 = NANOS_PER_SEC / 100; // Nanos per centisecond
const NANOS_PER_DAY: i64 = 24 * NANOS_PER_HOUR;

// Nanoseconds after UNIX epoch
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(i64);

impl std::ops::Add for Timestamp {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for Timestamp {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Timestamp {
    pub const TIMEZONE_OFFSET: i64 = 9 * NANOS_PER_HOUR; // KRX is GMT +9

    pub const fn from_secs_and_nanos(secs: i64, nsecs: i64) -> Self {
        Self(secs * NANOS_PER_SEC + nsecs)
    }

    pub const fn delta_time_after_midnight(hour: u64, min: u64, sec: u64, cent: u64) -> Self {
        let day_nanos = hour * (NANOS_PER_HOUR as u64)
                + min * (NANOS_PER_MIN as u64) // Cast the constants instead of hour/min/sec/cent
                + sec * (NANOS_PER_SEC as u64)
                + cent * (NANOS_PER_CENT as u64);
        Self(day_nanos as i64)
    }

    /// Returns the midnight timestamp at the given timezone
    pub fn get_midnight_at_timezone<const TIMEZONE: i64>(&self) -> Self {
        let time_at_timezone = self.0 + TIMEZONE;
        let days_since_epoch = time_at_timezone / NANOS_PER_DAY;
        let nanos_midnight = days_since_epoch * NANOS_PER_DAY;
        Self(nanos_midnight - TIMEZONE)
    }

    /// Convert into the HHMMSSuu format given the midnight timestamp
    pub fn format_hhmmssuu(&self, midnight: Timestamp) -> [u8; 8] {
        #[inline(always)]
        fn write_digits_fast<const OFFSET: usize>(buf: &mut [u8; 8], val: u8) {
            let (tens, ones) = (val / 10, val % 10);
            buf[OFFSET] = tens + b'0';
            buf[OFFSET + 1] = ones + b'0';
        }

        let mut out = [0u8; 8];

        let day_nanos = self.0 - midnight.0;

        let hour = day_nanos / NANOS_PER_HOUR;
        let min = (day_nanos % NANOS_PER_HOUR) / NANOS_PER_MIN;
        let sec = (day_nanos % NANOS_PER_MIN) / NANOS_PER_SEC;
        let cent = (day_nanos % NANOS_PER_SEC) / NANOS_PER_CENT;

        write_digits_fast::<0>(&mut out, hour as u8);
        write_digits_fast::<2>(&mut out, min as u8);
        write_digits_fast::<4>(&mut out, sec as u8);
        write_digits_fast::<6>(&mut out, cent as u8);

        out
    }
}
