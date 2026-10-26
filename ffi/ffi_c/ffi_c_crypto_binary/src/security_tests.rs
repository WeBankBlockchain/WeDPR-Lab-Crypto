use wedpr_ffi_common::utils::{CInputBuffer, COutputBuffer, FAILURE, SUCCESS};

fn input(bytes: &[u8]) -> CInputBuffer {
    CInputBuffer {
        data: bytes.as_ptr().cast(),
        len: bytes.len(),
    }
}

#[cfg(feature = "wedpr_f_vrf_secp256k1")]
#[test]
fn legacy_secp256k1_vrf_fails_without_releasing_outputs() {
    use crate::vrf_secp256k1::*;
    let secret = [1u8; 32];
    let mut bytes = [99u8; 128];
    let mut output = COutputBuffer {
        data: bytes.as_mut_ptr().cast(),
        len: bytes.len(),
    };
    unsafe {
        assert_eq!(
            wedpr_secp256k1_vrf_prove_utf8(
                &input(&secret),
                &input(b"message"),
                &mut output
            ),
            FAILURE
        );
        assert_eq!(bytes, [99u8; 128]);
        let proof = [0u8; 97];
        assert_eq!(
            wedpr_secp256k1_vrf_proof_to_hash(&input(&proof), &mut output),
            FAILURE
        );
        assert_eq!(bytes, [99u8; 128]);
        assert_eq!(
            wedpr_secp256k1_vrf_derive_public_key(
                &input(&[0u8; 32]),
                &mut output
            ),
            FAILURE
        );
        assert_eq!(bytes, [99u8; 128]);
        assert_eq!(
            wedpr_secp256k1_vrf_derive_public_key(&input(&secret), &mut output),
            SUCCESS
        );
        assert_eq!(output.len, 33);
        let public = bytes[..33].to_vec();
        bytes.fill(99);
        output.len = 128;
        assert_eq!(
            wedpr_secp256k1_vrf_prove_fast_utf8(
                &input(&secret),
                &input(&public),
                &input(b"message"),
                &mut output
            ),
            FAILURE
        );
        assert_eq!(
            wedpr_secp256k1_vrf_verify_utf8(
                &input(&public),
                &input(b"message"),
                &input(&proof)
            ),
            FAILURE
        );
        assert_eq!(bytes, [99u8; 128]);
        output.len = 1;
        assert_eq!(
            wedpr_secp256k1_vrf_derive_public_key(&input(&secret), &mut output),
            FAILURE
        );
        assert_eq!(output.len, 33);
        assert_eq!(bytes, [99u8; 128]);
    }
}

#[cfg(feature = "wedpr_f_hash_keccak256")]
#[test]
fn hash_rejects_invalid_descriptors_and_null_output() {
    let mut bytes = [99u8; 32];
    let mut output = COutputBuffer {
        data: bytes.as_mut_ptr().cast(),
        len: bytes.len(),
    };
    assert_eq!(
        unsafe {
            crate::hash::wedpr_keccak256_hash(std::ptr::null(), &mut output)
        },
        FAILURE
    );
    assert_eq!(
        unsafe {
            crate::hash::wedpr_keccak256_hash(
                &input(b"test"),
                std::ptr::null_mut(),
            )
        },
        FAILURE
    );
    let invalid = CInputBuffer {
        data: std::ptr::null(),
        len: 1,
    };
    assert_eq!(
        unsafe { crate::hash::wedpr_keccak256_hash(&invalid, &mut output) },
        FAILURE
    );
    assert_eq!(bytes, [99u8; 32]);
    let empty = CInputBuffer {
        data: std::ptr::null(),
        len: 0,
    };
    assert_eq!(
        unsafe { crate::hash::wedpr_keccak256_hash(&empty, &mut output) },
        SUCCESS
    );
    let mut null_output = COutputBuffer {
        data: std::ptr::null_mut(),
        len: 32,
    };
    assert_eq!(
        unsafe {
            crate::hash::wedpr_keccak256_hash(&input(b"test"), &mut null_output)
        },
        FAILURE
    );
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[test]
fn signing_rejects_short_output_without_freeing_stack_inputs() {
    let secret = [1u8; 32];
    let message = [2u8; 32];
    let mut bytes = [99u8; 1];
    let mut output = COutputBuffer {
        data: bytes.as_mut_ptr().cast(),
        len: bytes.len(),
    };
    assert_eq!(
        unsafe {
            crate::signature::wedpr_secp256k1_sign(
                &input(&secret),
                &input(&message),
                &mut output,
            )
        },
        FAILURE
    );
    assert_eq!(output.len, 1);
    assert_eq!(bytes, [99u8]);
    assert_eq!(secret, [1u8; 32]);
    let mut signature = [0u8; 65];
    output.data = signature.as_mut_ptr().cast();
    output.len = signature.len();
    assert_eq!(
        unsafe {
            crate::signature::wedpr_secp256k1_sign(
                &input(&secret),
                &input(&message),
                &mut output,
            )
        },
        SUCCESS
    );
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[test]
fn native_ed25519_rejects_an_identity_key_and_identity_signature() {
    let mut public = [0u8; 32];
    public[0] = 1;
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&public);
    assert_eq!(
        unsafe {
            crate::signature::wedpr_ed25519_verify(
                &input(&public),
                &input(b"untrusted message"),
                &input(&signature),
            )
        },
        FAILURE
    );
}
