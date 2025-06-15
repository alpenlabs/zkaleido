/// Mask to clear out the two most significant bits when reconstructing an Fq element
/// from a compressed representation.
///
/// These two bits encode the `CompressedPointFlag` for G1 points (positive, negative, or infinity).
/// Gnark (and arkworks) use the 2 most significant bits to encode the flag for a compressed
/// G1 point.
/// https://github.com/Consensys/gnark-crypto/blob/a7d721497f2a98b1f292886bb685fd3c5a90f930/ecc/bn254/marshal.go#L32-L42
pub(crate) const MASK: u8 = 0b11 << 6;

/// Flag indicating the “positive” y‐coordinate branch of a compressed G1 point.
pub(crate) const COMPRESSED_POSITIVE: u8 = 0b10 << 6;

/// Flag indicating the “negative” y‐coordinate branch of a compressed G1 point.
pub(crate) const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;

/// Flag indicating the “point at infinity” in a compressed G2 representation.
pub(crate) const COMPRESSED_INFINITY: u8 = 0b01 << 6;
