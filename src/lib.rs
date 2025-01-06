mod md5;
mod sha;

pub use md5::MD5;
pub use sha::SHA1;

pub trait MAC {
    /// The size of the blocks this algorithm operates
    const BLOCK_SIZE: u16;
    /// The size of the outcoming block in Bits
    const DIGEST_SIZE: u16;
    /// The maximum size of the message that can be hashed(in Bits). 0 means Inf.
    const MAX_SIZE: usize;
    /// The size of the working variables in Bits
    const WORD_SIZE: u16;

    /// Digest out of the algorithm
    type Digest;

    /// The Hashing function
    fn hash(v: Vec<u8>) -> Self::Digest;
}
