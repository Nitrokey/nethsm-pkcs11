#[macro_export]
macro_rules! padded_str {
  ($src:expr, $len: expr) => {{
      let mut out = [b' '; $len];
      let count = std::cmp::min($src.len(), $len);
      out[..count].copy_from_slice(&$src.as_bytes()[..count]);
      out
  }};
}