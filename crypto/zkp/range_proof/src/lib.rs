// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Zero-knowledge proof (ZKP) functions for range proofs.

#[macro_use]
extern crate wedpr_l_macros;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use merlin::Transcript;
use wedpr_l_utils::error::WedprError;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use wedpr_l_crypto_zkp_utils::{get_random_scalar, BASEPOINT_G2};

/// Uses a smaller value to reduce time cost of using range proofs.
/// Uses a larger value to increase value limit of using range proofs.
/// This is a critical parameter which is recommended to be fixed to
/// prevent unexpected proof validity issues.
const RANGE_SIZE_IN_BITS: usize = 32;
const DEFAULT_BYTES_MESSAGE: &[u8] = b"WeDPR";

/// Proves whether a value belongs to (0, 2^RANGE_SIZE_IN_BITS - 1], and create
/// a commitment for the value with provided random blinding value and blinding
/// basepoint. It returns:
/// 1) the encoded string for the proof.
/// 2) the point representing the commitment created for the value.
pub fn prove_value_range_with_blinding_and_blinding_basepoint(
    value: u64,
    blinding: &Scalar,
    blinding_basepoint: &RistrettoPoint,
) -> (Vec<u8>, RistrettoPoint)
{
    let mut pc_gens = PedersenGens::default();
    // Allow replacing the blinding basepoint for customized protocol design.
    pc_gens.B_blinding = blinding_basepoint.clone();
    let bp_gens = BulletproofGens::new(RANGE_SIZE_IN_BITS, 1);
    let secret_value = value;
    let mut prover_transcript = Transcript::new(DEFAULT_BYTES_MESSAGE);
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        RANGE_SIZE_IN_BITS,
    )
    .expect("RangeProof prove_single should not fail");

    (
        proof.to_bytes(),
        committed_value
            .decompress()
            .expect("CompressedRistretto decompress should not fail"),
    )
}

/// Proves whether a value belongs to (0, 2^RANGE_SIZE_IN_BITS - 1], and create
/// a commitment for the value with provided random blinding value. It returns:
/// 1) the encoded string for the proof.
/// 2) the point representing the commitment created for the value.
pub fn prove_value_range_with_blinding(
    value: u64,
    blinding: &Scalar,
) -> (Vec<u8>, RistrettoPoint)
{
    let (proof, value_commitment_point) =
        prove_value_range_with_blinding_and_blinding_basepoint(
            value,
            &blinding,
            // Cannot use BASEPOINT_G1 which has already been used by
            // commitment generation.
            &BASEPOINT_G2,
        );
    (proof, value_commitment_point)
}

/// Proves whether a value belongs to (0, 2^RANGE_SIZE_IN_BITS - 1], and create
/// a commitment for the value. It returns:
/// 1) the encoded string for the proof.
/// 2) the point representing the commitment created for the value.
/// 3) the random blinding value used in the above commitment.
pub fn prove_value_range(value: u64) -> (Vec<u8>, RistrettoPoint, Scalar) {
    let blinding = get_random_scalar();
    let (proof, value_commitment_point) =
        prove_value_range_with_blinding(value, &blinding);

    (proof, value_commitment_point, blinding)
}

/// Verifies whether a value embedded in the commentment belongs to
/// (0, 2^RANGE_SIZE_IN_BITS - 1], and use provided blinding basepoint.
pub fn verify_value_range_with_blinding_basepoint(
    commitment: &RistrettoPoint,
    proof_bytes: &[u8],
    blinding_basepoint: &RistrettoPoint,
) -> bool
{
    let mut pc_gens = PedersenGens::default();
    // Allow replacing the blinding basepoint for customized protocol design.
    pc_gens.B_blinding = blinding_basepoint.clone();
    let bp_gens = BulletproofGens::new(RANGE_SIZE_IN_BITS, 1);
    let mut verifier_transcript = Transcript::new(DEFAULT_BYTES_MESSAGE);
    let commitment_value = commitment.compress();

    let proof = match RangeProof::from_bytes(proof_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };

    match proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &commitment_value,
        RANGE_SIZE_IN_BITS,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Verifies whether a value embedded in the commentment belongs to
/// (0, 2^RANGE_SIZE_IN_BITS - 1].
pub fn verify_value_range(commitment: &RistrettoPoint, proof: &[u8]) -> bool {
    // Cannot use BASEPOINT_G1 which has already been used by commitment
    // generation.
    verify_value_range_with_blinding_basepoint(commitment, proof, &BASEPOINT_G2)
}

/// Proves whether all values in the list belongs to
/// (0, 2^RANGE_SIZE_IN_BITS - 1], and create commitments for them with provided
/// random blinding values and blinding basepoint.
/// It returns:
/// 1) the encoded string for the aggregated proof.
/// 2) the point list representing the commitments created for the values.
pub fn prove_value_range_in_batch(
    values: &[u64],
    blindings: &[Scalar],
    blinding_basepoint: &RistrettoPoint,
) -> Result<(Vec<u8>, Vec<RistrettoPoint>), WedprError>
{
    // Two slices should have the same length, and the length should be a
    // multiple of 2.
    if values.len() != blindings.len() || values.len() & 0x1 != 0 {
        return Err(WedprError::ArgumentError);
    }
    let mut pc_gens = PedersenGens::default();
    // Allow replacing the blinding basepoint for customized protocol design.
    pc_gens.B_blinding = blinding_basepoint.clone();
    let bp_gens = BulletproofGens::new(RANGE_SIZE_IN_BITS, values.len());
    let mut prover_transcript = Transcript::new(DEFAULT_BYTES_MESSAGE);
    let (proof, committed_value) = match RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        values,
        &blindings,
        RANGE_SIZE_IN_BITS,
    ) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("prove_value_range_in_batch failed");
            return Err(WedprError::FormatError);
        },
    };
    let vector_commitment = committed_value
        .iter()
        .map(|i| {
            i.decompress()
                .expect("CompressedRistretto decompress should not fail")
        })
        .collect();
    Ok((proof.to_bytes(), vector_commitment))
}

/// Verifies whether all values embedded in the commentment list belongs to
/// (0, 2^RANGE_SIZE_IN_BITS - 1].
pub fn verify_value_range_in_batch(
    commitments: &Vec<RistrettoPoint>,
    proof_bytes: &[u8],
    blinding_basepoint: &RistrettoPoint,
) -> bool
{
    let mut pc_gens = PedersenGens::default();
    // Allow replacing the blinding basepoint for customized protocol design.
    pc_gens.B_blinding = blinding_basepoint.clone();
    let bp_gens = BulletproofGens::new(RANGE_SIZE_IN_BITS, commitments.len());
    let mut verifier_transcript = Transcript::new(DEFAULT_BYTES_MESSAGE);
    // The length of decode_proof_result should be a multiple of 32 bytes.
    let decode_commit: Vec<CompressedRistretto> =
        commitments.iter().map(|i| i.compress()).collect();

    let proof = match RangeProof::from_bytes(proof_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    match proof.verify_multiple(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &decode_commit,
        RANGE_SIZE_IN_BITS,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof() {
        // Range proof for a single value.
        let (proof_c1, c1_point, _) = prove_value_range(1);
        assert_eq!(true, verify_value_range(&c1_point, &proof_c1));

        // A negative value will fail when it is out of the expected range after
        // the conversion.
        let (proof_c2, c2_point, _) = prove_value_range(-1i64 as u64);
        assert_eq!(false, verify_value_range(&c2_point, &proof_c2));

        // Range proof for a list of values.
        let blinding_basepoint = *BASEPOINT_G2;
        let values: Vec<u64> = vec![1, 2, 3, 4];
        let blindings: Vec<Scalar> =
            (0..values.len()).map(|_| get_random_scalar()).collect();

        let (proof_batch, point_list) = prove_value_range_in_batch(
            &values,
            &blindings,
            &blinding_basepoint,
        )
        .unwrap();

        assert_eq!(
            true,
            verify_value_range_in_batch(
                &point_list,
                &proof_batch,
                &blinding_basepoint,
            )
        );

        // Since the input size is not a multiple of 2, the batch prove function
        // will fail.
        let values2: Vec<u64> = vec![1, 2, 3];
        let blindings2: Vec<Scalar> =
            (0..values2.len()).map(|_| get_random_scalar()).collect();

        assert_eq!(
            WedprError::ArgumentError,
            prove_value_range_in_batch(
                &values2,
                &blindings2,
                &blinding_basepoint,
            )
            .unwrap_err()
        );
    }
}
