pub(crate) const VK_HASH_PREFIX_LENGTH: usize = 4;
pub(crate) const GROTH16_PROOF_LENGTH: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompressedPointFlag {
    Positive = COMPRESSED_POSITIVE as isize,
    Negative = COMPRESSED_NEGATIVE as isize,
    Infinity = COMPRESSED_INFINITY as isize,
}

impl From<u8> for CompressedPointFlag {
    fn from(val: u8) -> Self {
        match val {
            COMPRESSED_POSITIVE => CompressedPointFlag::Positive,
            COMPRESSED_NEGATIVE => CompressedPointFlag::Negative,
            COMPRESSED_INFINITY => CompressedPointFlag::Infinity,
            _ => panic!("Invalid compressed point flag"),
        }
    }
}

impl From<CompressedPointFlag> for u8 {
    fn from(value: CompressedPointFlag) -> Self {
        value as u8
    }
}
