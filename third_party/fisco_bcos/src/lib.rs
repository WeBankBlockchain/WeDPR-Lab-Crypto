// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! FISCO BCOS specific functions.

use bigint::Gas;
use sputnikvm::Precompiled;
use sputnikvm_precompiled_bn128::{
    BN128_ADD_PRECOMPILED, BN128_MUL_PRECOMPILED, BN128_PAIRING_PRECOMPILED,
};
use wedpr_l_utils::error::WedprError;

/// FISCO BCOS precompiled alt_bn128_G1_add function,
/// returns an error object if any points in pairing_data does not
/// belong the BN128 curve.
// TODO: Add detailed explanation for pairing_data format.
pub fn alt_bn128_g1_add<T: ?Sized + AsRef<[u8]>>(
    pairing_data: &T,
) -> Result<Vec<u8>, WedprError> {
    let (_, output) = match BN128_ADD_PRECOMPILED
        .gas_and_step(pairing_data.as_ref(), Gas::max_value())
    {
        Ok(v) => v,
        Err(_) => return Err(WedprError::ArgumentError),
    };
    return Ok(output.to_vec());
}

/// FISCO BCOS precompiled alt_bn128_G1_mul function,
/// returns an error object if any points in pairing_data does not
/// belong the BN128 curve.
// TODO: Add detailed explanation for pairing_data format.
pub fn alt_bn128_g1_mul<T: ?Sized + AsRef<[u8]>>(
    pairing_data: &T,
) -> Result<Vec<u8>, WedprError> {
    let (_, output) = match BN128_MUL_PRECOMPILED
        .gas_and_step(pairing_data.as_ref(), Gas::max_value())
    {
        Ok(v) => v,
        Err(_) => return Err(WedprError::ArgumentError),
    };
    return Ok(output.to_vec());
}

/// FISCO BCOS precompiled alt_bn128_pairing_product function,
/// returns an error object if any points in pairing_data does not
/// belong the BN128 curve.
// TODO: Add detailed explanation for pairing_data format.
pub fn alt_bn128_pairing_product<T: ?Sized + AsRef<[u8]>>(
    pairing_data: &T,
) -> Result<Vec<u8>, WedprError> {
    let (_, output) = match BN128_PAIRING_PRECOMPILED
        .gas_and_step(pairing_data.as_ref(), Gas::max_value())
    {
        Ok(v) => v,
        Err(_) => return Err(WedprError::ArgumentError),
    };
    return Ok(output.to_vec());
}

#[cfg(test)]
mod tests {
    use super::*;

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
