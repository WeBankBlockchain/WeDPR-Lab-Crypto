// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! 1/2 Oblivious transfer (OT) functions.

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, point_to_bytes, BASEPOINT_G1,
};

#[derive(Default, Debug, Clone)]
pub struct DataOneOutOfTwo {
    pub data0: Vec<u8>,
    pub data1: Vec<u8>,
}

#[derive(Default, Debug, Clone)]
pub struct EncryptPairOneOutOfTwo {
    pub point_w: RistrettoPoint,
    pub encrypt_message: Vec<u8>,
}

#[derive(Default, Debug, Clone)]
pub struct EncryptOneOutOfTwo {
    pub encrypt0: EncryptPairOneOutOfTwo,
    pub encrypt1: EncryptPairOneOutOfTwo,
}

pub fn receiver_init_1_out_of_2(
    choice: bool,
) -> (Scalar, RistrettoPoint, RistrettoPoint, RistrettoPoint) {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let c_id = blinding_a * blinding_b;
    let point_x =
        RistrettoPoint::multiscalar_mul(&[blinding_a], &[*BASEPOINT_G1]);
    let point_y =
        RistrettoPoint::multiscalar_mul(&[blinding_b], &[*BASEPOINT_G1]);
    let point_z: RistrettoPoint;
    if choice {
        point_z = RistrettoPoint::multiscalar_mul(&[c_id - Scalar::one()], &[
            *BASEPOINT_G1,
        ]);
    } else {
        point_z = RistrettoPoint::multiscalar_mul(&[c_id], &[*BASEPOINT_G1]);
    }
    (blinding_b, point_x, point_y, point_z)
}

pub fn sender_init_1_out_of_2(
    data: &DataOneOutOfTwo,
    point_x: &RistrettoPoint,
    point_y: &RistrettoPoint,
    point_z: &RistrettoPoint,
) -> EncryptOneOutOfTwo {
    let point_z1 = point_z + *BASEPOINT_G1;

    // compute zero ot
    let blinding_r0 = get_random_scalar();
    let blinding_s0 = get_random_scalar();
    let point_w0 =
        RistrettoPoint::multiscalar_mul(&[blinding_s0, blinding_r0], &[
            *point_x,
            *BASEPOINT_G1,
        ]);
    let point_key0 =
        RistrettoPoint::multiscalar_mul(&[blinding_s0, blinding_r0], [
            point_z, point_y,
        ]);
    let bytes_key0 = point_to_bytes(&point_key0);
    let encrypt_message0: Vec<u8> = data
        .data0
        .iter()
        .zip(bytes_key0.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    // compute one ot
    let blinding_r1 = get_random_scalar();
    let blinding_s1 = get_random_scalar();
    let point_w1 =
        RistrettoPoint::multiscalar_mul(&[blinding_s1, blinding_r1], &[
            *point_x,
            *BASEPOINT_G1,
        ]);
    let point_key1 =
        RistrettoPoint::multiscalar_mul(&[blinding_s1, blinding_r1], &[
            point_z1, *point_y,
        ]);
    let bytes_key1 = point_to_bytes(&point_key1);
    let encrypt_message1: Vec<u8> = data
        .data1
        .iter()
        .zip(bytes_key1.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    EncryptOneOutOfTwo {
        encrypt0: EncryptPairOneOutOfTwo {
            point_w: point_w0,
            encrypt_message: encrypt_message0,
        },
        encrypt1: EncryptPairOneOutOfTwo {
            point_w: point_w1,
            encrypt_message: encrypt_message1,
        },
    }
}

pub fn receiver_decrypt_1_out_of_2(
    choice: bool,
    blinding_b: &Scalar,
    sender_public: &EncryptOneOutOfTwo,
) -> Vec<u8> {
    if choice {
        let point_key =
            RistrettoPoint::multiscalar_mul([blinding_b], [sender_public
                .encrypt1
                .point_w]);
        let bytes_key = point_to_bytes(&point_key);
        let decrypt_message: Vec<u8> = sender_public
            .encrypt1
            .encrypt_message
            .iter()
            .zip(bytes_key.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        return decrypt_message;
    }
    let point_key =
        RistrettoPoint::multiscalar_mul([blinding_b], [sender_public
            .encrypt0
            .point_w]);
    let bytes_key = point_to_bytes(&point_key);
    let decrypt_message: Vec<u8> = sender_public
        .encrypt0
        .encrypt_message
        .iter()
        .zip(bytes_key.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    return decrypt_message;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_base_ot_1_out_of_2() {
        let data = DataOneOutOfTwo {
            data0: "wedpr test1".as_bytes().to_vec(),
            data1: "wedpr test2".as_bytes().to_vec(),
        };
        let choice = true;
        let (blinding_b, point_x, point_y, point_z) =
            receiver_init_1_out_of_2(choice);
        let sender_public =
            sender_init_1_out_of_2(&data, &point_x, &point_y, &point_z);
        let decrypt_message =
            receiver_decrypt_1_out_of_2(choice, &blinding_b, &sender_public);
        assert_eq!(decrypt_message, "wedpr test2".as_bytes().to_vec());
    }
}
