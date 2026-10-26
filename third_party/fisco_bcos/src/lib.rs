// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! FISCO BCOS alt_bn128 operations with EIP-196/EIP-197 encodings.
//! These interfaces operate on public points and scalars, not private keys.

#![forbid(unsafe_code)]

use bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};
use wedpr_l_utils::error::WedprError;

fn field(bytes: &[u8]) -> Result<Fq, WedprError> {
    // Reject noncanonical coordinates >= p instead of reducing them.
    Fq::from_slice(bytes).map_err(|_| WedprError::ArgumentError)
}

// Internal callers always supply exactly 64/128 bytes respectively.
fn g1(bytes: &[u8]) -> Result<G1, WedprError> {
    let x = field(&bytes[..32])?;
    let y = field(&bytes[32..64])?;
    if x.is_zero() && y.is_zero() {
        return Ok(G1::zero());
    }
    AffineG1::new(x, y)
        .map(Into::into)
        .map_err(|_| WedprError::ArgumentError)
}

fn g2(bytes: &[u8]) -> Result<G2, WedprError> {
    // EIP-197 encodes imaginary coefficient first, while Fq2::new takes
    // the real coefficient first.
    let x = Fq2::new(field(&bytes[32..64])?, field(&bytes[..32])?);
    let y = Fq2::new(field(&bytes[96..128])?, field(&bytes[64..96])?);
    if x.is_zero() && y.is_zero() {
        return Ok(G2::zero());
    }
    // The checked affine constructor enforces the curve and subgroup order.
    AffineG2::new(x, y)
        .map(Into::into)
        .map_err(|_| WedprError::ArgumentError)
}

fn encode_g1(point: G1) -> Result<Vec<u8>, WedprError> {
    let mut output = vec![0u8; 64];
    if let Some(affine) = AffineG1::from_jacobian(point) {
        affine
            .x()
            .to_big_endian(&mut output[..32])
            .map_err(|_| WedprError::FormatError)?;
        affine
            .y()
            .to_big_endian(&mut output[32..])
            .map_err(|_| WedprError::FormatError)?;
    }
    Ok(output)
}

fn padded_prefix<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    let count = input.len().min(N);
    output[..count].copy_from_slice(&input[..count]);
    output
}

/// Add two G1 points. Short input is right-padded with zeros; bytes beyond
/// 128 are ignored, as required by EIP-196. Output is always 64 bytes.
pub fn alt_bn128_g1_add<T: ?Sized + AsRef<[u8]>>(
    pairing_data: &T,
) -> Result<Vec<u8>, WedprError> {
    let input = padded_prefix::<128>(pairing_data.as_ref());
    encode_g1(g1(&input[..64])? + g1(&input[64..])?)
}

/// Multiply a G1 point by any 256-bit scalar (reduced modulo the group order).
/// Short input is right-padded; bytes beyond 96 are ignored (EIP-196).
pub fn alt_bn128_g1_mul<T: ?Sized + AsRef<[u8]>>(
    pairing_data: &T,
) -> Result<Vec<u8>, WedprError> {
    let input = padded_prefix::<96>(pairing_data.as_ref());
    let scalar =
        Fr::from_slice(&input[64..]).map_err(|_| WedprError::ArgumentError)?;
    encode_g1(g1(&input[..64])? * scalar)
}

/// Check an EIP-197 pairing product. Length must be a multiple of 192; empty
/// input is true. Return exactly 32 bytes encoding 0 or 1, or fail on an invalid
/// coordinate, curve point or G2 subgroup element.
pub fn alt_bn128_pairing_product<T: ?Sized + AsRef<[u8]>>(
    pairing_data: &T,
) -> Result<Vec<u8>, WedprError> {
    let input = pairing_data.as_ref();
    if input.len() % 192 != 0 {
        return Err(WedprError::ArgumentError);
    }
    let mut pairs = Vec::with_capacity(input.len() / 192);
    for pair in input.chunks_exact(192) {
        pairs.push((g1(&pair[..64])?, g2(&pair[64..])?));
    }
    let valid = pairs.is_empty() || pairing_batch(&pairs) == Gt::one();
    let mut output = vec![0u8; 32];
    output[31] = u8::from(valid);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generator() -> Vec<u8> {
        let mut point = vec![0u8; 64];
        point[31] = 1;
        point[63] = 2;
        point
    }

    #[test]
    fn preserves_eip196_vectors_padding_and_full_width_scalars() {
        let generator = generator();
        // Independent integer double-and-add calculation over the EIP field.
        let doubled = hex::decode(concat!(
            "030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3",
            "15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4"
        ))
        .unwrap();
        let mut addition = generator.clone();
        addition.extend_from_slice(&generator);
        assert_eq!(alt_bn128_g1_add(&addition).unwrap(), doubled);
        addition.extend_from_slice(&[0xffu8; 128]);
        assert_eq!(alt_bn128_g1_add(&addition).unwrap(), doubled);
        // Missing second point is infinity, with virtual right-padding.
        assert_eq!(alt_bn128_g1_add(&generator).unwrap(), generator);

        let mut multiplication = generator.clone();
        multiplication.extend_from_slice(&[0u8; 32]);
        multiplication[95] = 2;
        assert_eq!(alt_bn128_g1_mul(&multiplication).unwrap(), doubled);
        multiplication.extend_from_slice(&[0xffu8; 96]);
        assert_eq!(alt_bn128_g1_mul(&multiplication).unwrap(), doubled);
        multiplication.truncate(96);
        let order = hex::decode(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        )
        .unwrap();
        multiplication[64..].copy_from_slice(&order);
        assert_eq!(alt_bn128_g1_mul(&multiplication).unwrap(), vec![0u8; 64]);
        multiplication[95] += 1;
        assert_eq!(alt_bn128_g1_mul(&multiplication).unwrap(), generator);
        multiplication[64..].fill(0xff);
        assert_eq!(
            alt_bn128_g1_mul(&multiplication).unwrap(),
            hex::decode(concat!(
            "2f588cffe99db877a4434b598ab28f81e0522910ea52b45f0adaa772b2d5d3521",
            "2f42fa8fd34fb1b33d8c6a718b6590198389b26fc9d8808d971f8b009777a97"
        ))
            .unwrap()
        );
    }

    #[test]
    fn rejects_noncanonical_fields_and_invalid_pairing_lengths() {
        let modulus = hex::decode(
            "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
        )
        .unwrap();
        for offset in [0, 32, 64, 96] {
            let mut addition = vec![0u8; 128];
            addition[offset..offset + 32].copy_from_slice(&modulus);
            assert!(alt_bn128_g1_add(&addition).is_err());
        }
        for offset in (0..192).step_by(32) {
            let mut pair = vec![0u8; 192];
            pair[offset..offset + 32].copy_from_slice(&modulus);
            assert!(alt_bn128_pairing_product(&pair).is_err());
        }
        for length in [1, 191, 193, 383, 385] {
            assert!(alt_bn128_pairing_product(&vec![0u8; length]).is_err());
        }
    }

    #[test]
    fn pairing_generator_and_its_negative_cancel() {
        // EIP-197 generator, with imaginary coefficients encoded first.
        let second = hex::decode(concat!(
            "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
            "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
            "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
            "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
        ))
        .unwrap();
        let mut pair = generator();
        pair.extend_from_slice(&second);
        assert_eq!(alt_bn128_pairing_product(&pair).unwrap(), vec![0u8; 32]);
        let mut negative = generator();
        negative[32..].copy_from_slice(&hex::decode("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45").unwrap());
        pair.extend_from_slice(&negative);
        pair.extend_from_slice(&second);
        let mut one = vec![0u8; 32];
        one[31] = 1;
        assert_eq!(alt_bn128_pairing_product(&pair).unwrap(), one);
    }

    #[test]
    fn rejects_on_curve_g2_points_outside_the_prime_order_subgroup() {
        let inverse_82 = Fq::from_str("82").unwrap().inverse().unwrap();
        let twist_b = Fq2::new(
            Fq::from_str("27").unwrap() * inverse_82,
            -Fq::from_str("3").unwrap() * inverse_82,
        );
        let order = hex::decode(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        )
        .unwrap();
        for integer in 0..128 {
            let x = Fq2::new(
                Fq::from_str(&integer.to_string()).unwrap(),
                Fq::zero(),
            );
            if let Some(y) = (x * x * x + twist_b).sqrt() {
                // Build a known on-curve test point without the checked affine
                // constructor, then multiply by the full integer order without
                // reducing the scalar. This independently detects a bad subgroup.
                let point = G2::new(x, y, Fq2::one());
                let mut product = G2::zero();
                for byte in &order {
                    for bit in (0..8).rev() {
                        product = product + product;
                        if byte & (1 << bit) != 0 {
                            product = product + point;
                        }
                    }
                }
                if product.is_zero() {
                    continue;
                }
                let mut pair = vec![0u8; 192]; // infinity G1 must not bypass G2 checks
                x.imaginary().to_big_endian(&mut pair[64..96]).unwrap();
                x.real().to_big_endian(&mut pair[96..128]).unwrap();
                y.imaginary().to_big_endian(&mut pair[128..160]).unwrap();
                y.real().to_big_endian(&mut pair[160..192]).unwrap();
                assert!(alt_bn128_pairing_product(&pair).is_err());
                return;
            }
        }
        panic!("failed to construct the outside-subgroup test point");
    }

    #[test]
    fn test_bn128_add() {
        // Test zero points add.
        let zero_pairing_input = [0u8; 128];
        let output = alt_bn128_g1_add(&zero_pairing_input).unwrap();
        let expected = [0u8; 64];
        assert_eq!(output, expected.to_vec());

        // Test empty input.
        let empty_input = [0u8; 0];
        let output = alt_bn128_g1_add(&empty_input).unwrap();
        assert_eq!(output, expected);

        // Test a point not on curve.
        let bad_pairing_input = [1u8; 128];
        let output = alt_bn128_g1_add(&bad_pairing_input).unwrap_err();
        assert_eq!(output, WedprError::ArgumentError);
    }

    #[test]
    fn test_bn128_mul() {
        // Test zero points multiple.
        let zero_pairing_input = [0u8; 96];
        let output = alt_bn128_g1_mul(&zero_pairing_input).unwrap();
        let expected = [0u8; 64];
        assert_eq!(output, expected.to_vec());

        // Test empty input.
        let empty_input = [0u8; 0];
        let output = alt_bn128_g1_mul(&empty_input).unwrap();
        assert_eq!(output, expected);

        // Test a point not on curve.
        let bad_pairing_input = [1u8; 96];
        let output = alt_bn128_g1_mul(&bad_pairing_input).unwrap_err();
        assert_eq!(output, WedprError::ArgumentError);
    }

    #[test]
    fn test_bn128_paring() {
        // Test zero points paring.
        let zero_pairing_input = [0u8; 192];
        let output = alt_bn128_pairing_product(&zero_pairing_input).unwrap();
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(output, expected);

        // Test empty input.
        let empty_input = [0u8; 0];
        let output = alt_bn128_pairing_product(&empty_input).unwrap();
        assert_eq!(output, expected);

        // Test a point not on curve.
        let bad_pairing_input = [1u8; 192];
        let output = alt_bn128_pairing_product(&bad_pairing_input).unwrap_err();
        assert_eq!(output, WedprError::ArgumentError);

        // Test a point with known output.
        let known_pairing_input = hex::decode(
            "2eca0c7238bf16e83e7a1e6c5d49540685ff51380f309842a98561558019fc0203d3260361\
            bb8451de5ff5ecd17f010ff22f5c31cdf184e9020b06fa5997db841213d2149b006137fcfb\
            23036606f848d638d576a120ca981b5b1a5f9300b3ee2276cf730cf493cd95d64677bbb75f\
            c42db72513a4c1e387b476d056f80aa75f21ee6226d31426322afcda621464d0611d226783\
            262e21bb3bc86b537e986237096df1f82dff337dd5972e32a8ad43e28a78a96a823ef1cd4d\
            ebe12b6552ea5f06967a1237ebfeca9aaae0d6d0bab8e28c198c5a339ef8a2407e31cdac51\
            6db922160fa257a5fd5b280642ff47b65eca77e626cb685c84fa6d3b6882a283ddd1198e93\
            93920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76\
            426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad69\
            0c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1\
            e7690c43d37b4ce6cc0166fa7daa").unwrap();
        let output = alt_bn128_pairing_product(&known_pairing_input).unwrap();
        assert_eq!(output, expected);
    }
}
