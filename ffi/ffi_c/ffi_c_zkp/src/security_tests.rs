use super::discrete_logarithm_proof::*;
use wedpr_ffi_common::utils::{CInputBuffer, COutputBuffer, FAILURE, SUCCESS};
use wedpr_l_crypto_zkp_utils::{BASEPOINT_G1, BASEPOINT_G2};

fn input(bytes: &[u8]) -> CInputBuffer {
    CInputBuffer {
        data: bytes.as_ptr().cast(),
        len: bytes.len(),
    }
}

#[test]
fn proof_generation_reports_short_output_and_preserves_caller_memory() {
    let zero_blinding = [0u8; 32];
    let g = BASEPOINT_G1.compress().to_bytes();
    let h = BASEPOINT_G2.compress().to_bytes();
    let mut bytes = [99u8; 1];
    let mut output = COutputBuffer {
        data: bytes.as_mut_ptr().cast(),
        len: 1,
    };
    assert_eq!(
        unsafe {
            wedpr_generate_prove_knowledge_proof(
                42,
                &input(&zero_blinding),
                &input(&g),
                &input(&h),
                &mut output,
            )
        },
        FAILURE
    );
    assert_eq!(output.len, 96);
    assert_eq!(bytes, [99u8]);
    let mut proof = vec![0u8; output.len];
    output.data = proof.as_mut_ptr().cast();
    assert_eq!(
        unsafe {
            wedpr_generate_prove_knowledge_proof(
                42,
                &input(&zero_blinding),
                &input(&g),
                &input(&h),
                &mut output,
            )
        },
        SUCCESS
    );
    let commitment = (*BASEPOINT_G1
        * curve25519_dalek::scalar::Scalar::from(42u64))
    .compress()
    .to_bytes();
    assert_eq!(
        unsafe {
            wedpr_verify_knowledge_proof(
                &input(&commitment),
                &input(&proof),
                &input(&g),
                &input(&h),
            )
        },
        SUCCESS
    );
    proof.push(0);
    assert_eq!(
        unsafe {
            wedpr_verify_knowledge_proof(
                &input(&commitment),
                &input(&proof),
                &input(&g),
                &input(&h),
            )
        },
        FAILURE
    );
}

#[test]
fn native_proof_generation_rejects_a_noncanonical_scalar_without_writing() {
    let mut noncanonical = [0u8; 32];
    noncanonical[31] = 0x80;
    let g = BASEPOINT_G1.compress().to_bytes();
    let h = BASEPOINT_G2.compress().to_bytes();
    let mut proof = [99u8; 96];
    let mut output = COutputBuffer {
        data: proof.as_mut_ptr().cast(),
        len: proof.len(),
    };
    assert_eq!(
        unsafe {
            wedpr_generate_prove_knowledge_proof(
                42,
                &input(&noncanonical),
                &input(&g),
                &input(&h),
                &mut output,
            )
        },
        FAILURE
    );
    assert_eq!(proof, [99u8; 96]);
}
