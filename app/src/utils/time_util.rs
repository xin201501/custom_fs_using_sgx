use anyhow::anyhow;
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::time::{self, Duration, SystemTime, UNIX_EPOCH};
/// represent current time with seconds and fraction of a second in nanoseconds
#[derive(Serialize, Deserialize, Debug, Copy, Clone, Default, PartialEq, Encode, Decode)]
pub struct TimeDurationStruct {
    /// seconds
    pub sec: u64,
    /// fraction of a second in nanoseconds
    pub nsec: u32,
}

/// calculate what time is it since `1970-1-1 00:00:00`,named as [UNIX_EPOCH]
pub fn now() -> TimeDurationStruct {
    let now = SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
    TimeDurationStruct {
        sec: now.as_secs(),
        nsec: now.subsec_nanos(),
    }
}

impl From<TimeDurationStruct> for SystemTime {
    fn from(value: TimeDurationStruct) -> Self {
        let duration = Duration::new(value.sec, value.nsec);
        UNIX_EPOCH + duration
    }
}

impl TryFrom<SystemTime> for TimeDurationStruct {
    type Error = anyhow::Error;
    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(TimeDurationStruct {
                sec: duration.as_secs(),
                nsec: duration.subsec_nanos(),
            }),
            Err(before_epoch_error) => Err(anyhow!(
                "doesn't support time before UNIX_EPOCH: {}",
                before_epoch_error
            )),
        }
    }
}
