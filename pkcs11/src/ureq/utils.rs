use std::io::{self, ErrorKind};

use ureq::unversioned::transport::{time::Duration, NextTimeout};

/// Windows causes kind `TimedOut` while unix does `WouldBlock`. Since we are not
/// using non-blocking streams, we normalize `WouldBlock` -> `TimedOut`.
pub(crate) trait IoResultExt {
    fn normalize_would_block(self) -> Self;
}

impl<T> IoResultExt for io::Result<T> {
    fn normalize_would_block(self) -> Self {
        match self {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                Err(io::Error::new(ErrorKind::TimedOut, e))
            }
            Err(e) => Err(e),
        }
    }
}
pub(crate) fn timeout_not_zero(this: &NextTimeout) -> Option<Duration> {
    if this.after.is_not_happening() {
        None
    } else if this.after.is_zero() {
        Some(Duration::from_secs(1))
    } else {
        Some(this.after)
    }
}
