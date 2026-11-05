//! Reads with a bound: hostile input must not grow memory or stall the hook.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

/// The most a hook payload or `decide` request may hold.
pub const MAX_INPUT: usize = 4 << 20;

/// Reads `r` to the end, up to `max` bytes. None if there is more.
pub fn read_capped(r: &mut dyn Read, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut b = Vec::new();
    r.take(max as u64 + 1).read_to_end(&mut b)?;
    Ok((b.len() <= max).then_some(b))
}

/// The last `max` bytes of `f`. When the file is longer, the first line is cut
/// in the middle and is left out.
pub(crate) fn read_tail(mut f: File, max: u64) -> io::Result<Vec<u8>> {
    let size = f.metadata()?.len();
    let cut = size > max;
    if cut {
        f.seek(SeekFrom::Start(size - max))?;
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    if cut {
        buf = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => buf.split_off(i + 1),
            None => Vec::new(),
        };
    }
    Ok(buf)
}
