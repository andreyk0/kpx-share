//! Bytes that may be a secret: decrypted database XML, field values, attachments.

use std::fmt;
use std::io::{self, Read};

use zeroize::Zeroize;

/// Owned bytes that are wiped when dropped and never printed.
///
/// There is no `Display` and `Debug` prints no contents, not even the length, so a secret cannot
/// reach a log or an error message by formatting. Reading the bytes is the explicit
/// [`expose`](Self::expose).
///
/// Growth goes through [`extend_from_slice`](Self::extend_from_slice), which wipes the old buffer
/// on reallocation: a plain `Vec::push` would hand the old allocation back to the allocator with
/// the secret still in it.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// An empty buffer, the start of an incremental build.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Takes ownership of `bytes` without copying them.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Copies `bytes` into a buffer of exactly their length.
    #[must_use]
    pub fn copy_from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Reads `source` to its end, never leaving a partial copy behind in freed memory.
    ///
    /// # Errors
    /// Any error `source` returns other than `Interrupted`; what was read so far is wiped.
    pub fn read_to_end(mut source: impl Read) -> io::Result<Self> {
        const CHUNK_BYTES: usize = 8 * 1024;
        let mut chunk = [0u8; CHUNK_BYTES];
        let mut out = Self::new();
        let outcome = loop {
            match source.read(&mut chunk) {
                Ok(0) => break Ok(()),
                Ok(count) => match chunk.get(..count) {
                    Some(read) => out.extend_from_slice(read),
                    None => {
                        break Err(io::Error::other(
                            "reader reported more bytes than it was given",
                        ));
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => break Err(error),
            }
        };
        chunk.zeroize();
        outcome.map(|()| out)
    }

    /// Appends `bytes`; on reallocation the old buffer is wiped before it is freed.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let mut grown = Vec::with_capacity(needed.max(self.0.capacity().saturating_mul(2)));
            grown.extend_from_slice(&self.0);
            let mut old = std::mem::replace(&mut self.0, grown);
            old.zeroize();
        }
        self.0.extend_from_slice(bytes);
    }

    /// The secret itself. Every call site is a place the secret leaves this type.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for SecretBytes {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::copy_from(&self.0)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // `Vec::zeroize` wipes the whole capacity, not only `len` bytes.
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_contents_or_length() {
        let secret = SecretBytes::copy_from(b"hunter2");
        let printed = format!("{secret:?} {:?}", Some(&secret));
        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(!printed.contains('7'), "{printed}");
    }

    #[test]
    fn extend_across_reallocations_keeps_every_byte() {
        let mut secret = SecretBytes::new();
        for chunk in [&b"ab"[..], b"", b"cdefghijklmnop", b"q"] {
            secret.extend_from_slice(chunk);
        }
        assert_eq!(secret.expose(), b"abcdefghijklmnopq");
    }

    #[test]
    fn read_to_end_reads_past_one_chunk() {
        let source: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let secret = SecretBytes::read_to_end(&source[..]).unwrap();
        assert_eq!(secret.expose(), &source[..]);
    }
}
