use bn::Fq;

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

/// Flag indicating the "point at infinity" in a compressed G2 representation.
pub(crate) const COMPRESSED_INFINITY: u8 = 0b01 << 6;

/// Size of a u32 in bytes (for num_k)
pub(crate) const U32_SIZE: usize = std::mem::size_of::<u32>();

/// Size of an Fq field element in bytes
pub(crate) const FQ_SIZE: usize = std::mem::size_of::<Fq>();

// Size constants for serialization
/// Size of a GNARK-compressed G1 point in bytes
///
/// G1 is over Fq, so compressed format stores only x-coordinate (32 bytes) with flag bits
pub(crate) const G1_COMPRESSED_SIZE: usize = FQ_SIZE;

/// Size of an uncompressed G1 point in bytes
///
/// G1 is over Fq, so uncompressed format stores x + y coordinates (32 + 32 = 64 bytes)
pub(crate) const G1_UNCOMPRESSED_SIZE: usize = FQ_SIZE * 2;

/// Size of a GNARK-compressed G2 point in bytes
///
/// G2 is over Fq2, so compressed format stores only x-coordinate (64 bytes: 32 for real + 32 for
/// imaginary) with flag bits
pub(crate) const G2_COMPRESSED_SIZE: usize = FQ_SIZE * 2;

/// Size of an uncompressed G2 point in bytes
///
/// G2 is over Fq2, so uncompressed format stores x + y coordinates (64 + 64 = 128 bytes)
pub(crate) const G2_UNCOMPRESSED_SIZE: usize = G2_COMPRESSED_SIZE * 2;

// Groth16 Proof size constants
/// Size of a GNARK-compressed Groth16 proof in bytes (32 + 64 + 64)
pub const GROTH16_PROOF_COMPRESSED_SIZE: usize =
    G1_COMPRESSED_SIZE + G2_COMPRESSED_SIZE + G1_COMPRESSED_SIZE;

/// Size of an uncompressed Groth16 proof in bytes (64 + 128 + 64)
pub const GROTH16_PROOF_UNCOMPRESSED_SIZE: usize =
    G1_UNCOMPRESSED_SIZE + G2_UNCOMPRESSED_SIZE + G1_UNCOMPRESSED_SIZE;

/// Size of uncompressed VK header (without K points): 452 bytes
/// Layout: G1 alpha (64) + G2 beta (128) + G2 gamma (128) + G2 delta (128) + num_k (4)
pub(crate) const GROTH16_VK_UNCOMPRESSED_HEADER_SIZE: usize =
    G1_UNCOMPRESSED_SIZE + 3 * G2_UNCOMPRESSED_SIZE + U32_SIZE;

// GNARK Verifying Key offsets and sizes (GNARK format with Bellman-compatibility padding)
/// Offset for G2 beta in GNARK compressed VK format
/// After G1 alpha (32 bytes) + G1 beta (32 bytes, unused/Bellman-compatibility padding)
///
/// The padding exists because GNARK includes G1.Beta and G1.Delta for Bellman compatibility,
/// but these fields are not used in verification (only G2.Beta and G2.Delta are used).
/// [Reference](https://pkg.go.dev/github.com/consensys/gnark/backend/groth16/bn254#VerifyingKey>)
pub(crate) const GNARK_VK_COMPRESSED_G2_BETA_OFFSET: usize = G1_COMPRESSED_SIZE + FQ_SIZE;

/// Offset for G2 gamma in GNARK compressed VK format
/// After G1 alpha + G1 beta padding + G2 beta
pub(crate) const GNARK_VK_COMPRESSED_G2_GAMMA_OFFSET: usize =
    GNARK_VK_COMPRESSED_G2_BETA_OFFSET + G2_COMPRESSED_SIZE;

/// Offset for G2 delta in GNARK compressed VK format
/// After G2 gamma + G1 delta (32 bytes, unused/Bellman-compatibility padding)
///
/// The padding exists because GNARK includes G1.Delta for Bellman compatibility,
/// but this field is not used in verification (only G2.Delta is used).
pub(crate) const GNARK_VK_COMPRESSED_G2_DELTA_OFFSET: usize =
    GNARK_VK_COMPRESSED_G2_GAMMA_OFFSET + G2_COMPRESSED_SIZE + FQ_SIZE;

/// Offset for num_k in GNARK compressed VK format
/// After G2 delta
pub(crate) const GNARK_VK_COMPRESSED_NUM_K_OFFSET: usize =
    GNARK_VK_COMPRESSED_G2_DELTA_OFFSET + G2_COMPRESSED_SIZE;

/// Size of the GNARK compressed VK header (all fixed-size fields before variable-length K points).
/// The header contains: G1 alpha, G2 beta, G2 gamma, G2 delta (with GNARK padding), and num_k
/// field. This is also the offset where K points start in the buffer: 292 bytes
pub(crate) const GNARK_VK_COMPRESSED_HEADER_SIZE: usize =
    GNARK_VK_COMPRESSED_NUM_K_OFFSET + U32_SIZE;

/// Number of K points in SP1's Groth16 verifying key
pub(crate) const SP1_NUM_K: usize = 3;

/// Size of a GNARK-compressed SP1 Groth16 verifying key in bytes
/// Layout: header (292 bytes) + K points (2 * 32 = 64 bytes) = 356 bytes
pub const SP1_GROTH16_VK_COMPRESSED_SIZE: usize =
    GNARK_VK_COMPRESSED_HEADER_SIZE + (SP1_NUM_K * G1_COMPRESSED_SIZE);

/// Size of an uncompressed SP1 Groth16 verifying key in bytes
/// Layout: header (452 bytes) + K points (2 * 64 = 128 bytes) = 580 bytes
pub const SP1_GROTH16_VK_UNCOMPRESSED_SIZE: usize =
    GROTH16_VK_UNCOMPRESSED_HEADER_SIZE + (SP1_NUM_K * G1_UNCOMPRESSED_SIZE);
