use super::*;

#[test]
fn scalar_parser_rejects_alternate_encodings_instead_of_masking_or_reducing() {
    assert_eq!(
        bytes_to_scalar(&Scalar::one().to_bytes()).unwrap(),
        Scalar::one()
    );
    let mut high_bit = Scalar::one().to_bytes();
    high_bit[31] |= 0x80;
    assert!(bytes_to_scalar(&high_bit).is_err());
    // Little-endian order l: this is NOT the canonical encoding of zero.
    let order = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
        0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x10,
    ];
    assert!(bytes_to_scalar(&order).is_err());
    assert!(bytes_to_scalar(&[0xffu8; 32]).is_err());
    for length in 0..64 {
        if length != 32 {
            assert!(bytes_to_scalar(&vec![0u8; length]).is_err());
        }
    }
}

fn check_proof<T: Serialize + Deserialize>(proof: T) {
    let encoded = proof.serialize();
    assert!(T::deserialize(&encoded).is_ok());
    for length in 0..encoded.len() {
        assert!(T::deserialize(&encoded[..length]).is_err());
    }
    let mut appended = encoded.clone();
    appended.push(0);
    assert!(T::deserialize(&appended).is_err());
}

#[test]
fn proof_parsers_require_exact_lengths() {
    check_proof(BalanceProof::default());
    check_proof(KnowledgeProof::default());
    check_proof(FormatProof::default());
    check_proof(ArithmeticProof::default());
    check_proof(EqualityProof::default());
}
