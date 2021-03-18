// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! FISCO BCOS tools functions.

use bigint::Gas;
use sputnikvm::Precompiled;
use sputnikvm_precompiled_bn128::{
    BN128_ADD_PRECOMPILED, BN128_MUL_PRECOMPILED, BN128_PAIRING_PRECOMPILED,
};
use wedpr_l_utils::error::WedprError;

/// FISCO BCOS precompile alt_bn128_G1_add
// Can fail if any of the 2 points does not belong the bn128 curve
pub fn alt_bn128_g1_add<T: ?Sized + AsRef<[u8]>>(
    input_bytes: &T,
) -> Result<Vec<u8>, WedprError> {
    let (_, output) = match BN128_ADD_PRECOMPILED
        .gas_and_step(input_bytes.as_ref(), Gas::max_value())
    {
        Ok(v) => v,
        Err(_) => return Err(WedprError::ArgumentError),
    };
    return Ok(output.to_vec());
}

/// FISCO BCOS precompile alt_bn128_G1_mul
// Can fail if any of the 2 points does not belong the bn128 curve
pub fn alt_bn128_g1_mul<T: ?Sized + AsRef<[u8]>>(
    input_bytes: &T,
) -> Result<Vec<u8>, WedprError> {
    let (_, output) = match BN128_MUL_PRECOMPILED
        .gas_and_step(input_bytes.as_ref(), Gas::max_value())
    {
        Ok(v) => v,
        Err(_) => return Err(WedprError::ArgumentError),
    };
    return Ok(output.to_vec());
}

/// FISCO BCOS precompile alt_bn128_pairing_product
// Can fail if any of the 2 points does not belong the bn128 curve
pub fn alt_bn128_pairing_product<T: ?Sized + AsRef<[u8]>>(
    input_bytes: &T,
) -> Result<Vec<u8>, WedprError> {
    let (_, output) = match BN128_PAIRING_PRECOMPILED
        .gas_and_step(input_bytes.as_ref(), Gas::max_value())
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
        // test zero point add
        let input_bytes = [0u8; 128];
        let output = alt_bn128_g1_add(&input_bytes).unwrap();
        let expected = [0u8; 64];
        assert_eq!(output, expected.to_vec());

        // test empty input
        let empty_input = [0u8; 0];
        let output = alt_bn128_g1_add(&empty_input).unwrap();
        assert_eq!(output, expected);

        // should failed! point not on curve
        let input_bytes = [1u8; 128];
        let output = alt_bn128_g1_add(&input_bytes).unwrap_err();
        assert_eq!(output, WedprError::ArgumentError);
    }

    #[test]
    fn test_bn128_mul() {
        // test zero point multiple
        let input_bytes = [0u8; 96];
        let output = alt_bn128_g1_mul(&input_bytes).unwrap();
        let expected = [0u8; 64];
        assert_eq!(output, expected.to_vec());

        // test empty input
        let empty_input = [0u8; 0];
        let output = alt_bn128_g1_mul(&empty_input).unwrap();
        assert_eq!(output, expected);

        // should failed! point not on curve
        let input_bytes = [1u8; 96];
        let output = alt_bn128_g1_mul(&input_bytes).unwrap_err();
        assert_eq!(output, WedprError::ArgumentError);
    }

    #[test]
    fn test_bn128_paring() {
        // test zero point paring
        let input_bytes = [0u8; 192];
        let output = alt_bn128_pairing_product(&input_bytes).unwrap();
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(output, expected);

        // // test empty input
        let empty_input = [0u8; 0];
        let output = alt_bn128_pairing_product(&empty_input).unwrap();
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(output, expected);

        // should failed! point not on curve
        let input_bytes = [1u8; 192];
        let output = alt_bn128_pairing_product(&input_bytes).unwrap_err();
        assert_eq!(output, WedprError::ArgumentError);

        // should pass! test multi point
        let input_bytes = hex::decode("2eca0c7238bf16e83e7a1e6c5d49540685ff51380f309842a98561558019fc0203d3260361bb8451de5ff5ecd17f010ff22f5c31cdf184e9020b06fa5997db841213d2149b006137fcfb23036606f848d638d576a120ca981b5b1a5f9300b3ee2276cf730cf493cd95d64677bbb75fc42db72513a4c1e387b476d056f80aa75f21ee6226d31426322afcda621464d0611d226783262e21bb3bc86b537e986237096df1f82dff337dd5972e32a8ad43e28a78a96a823ef1cd4debe12b6552ea5f06967a1237ebfeca9aaae0d6d0bab8e28c198c5a339ef8a2407e31cdac516db922160fa257a5fd5b280642ff47b65eca77e626cb685c84fa6d3b6882a283ddd1198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa").unwrap();
        let output = alt_bn128_pairing_product(&input_bytes).unwrap();
        assert_eq!(output, expected);
    }
}
