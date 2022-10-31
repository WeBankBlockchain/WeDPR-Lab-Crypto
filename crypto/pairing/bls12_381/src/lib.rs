//! This module provides bls12_381 equality test

extern crate bls12_381;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use ff::Field;
use rand;
use sha2;
use wedpr_l_utils::error::WedprError;

#[macro_use]
extern crate wedpr_l_macros;

pub struct WedprBls128Cipher {
    u_point: G1Projective,
    v_point: G2Projective,
}

impl WedprBls128Cipher {
    pub fn to_bytes(&self) -> Vec<u8> {
        let u_point_bytes = G1Affine::from(self.u_point).to_compressed();

        let v_point_bytes = G2Affine::from(self.v_point).to_compressed();
        let result: Vec<u8> =
            [u_point_bytes.as_slice(), v_point_bytes.as_slice()].concat();
        return result;
    }

    pub fn from_bytes(message: &[u8]) -> Result<WedprBls128Cipher, WedprError> {
        if message.len() != 144 {
            return Err(WedprError::FormatError);
        }

        let mut u_point_bytes: [u8; 48] = [0; 48];
        u_point_bytes.copy_from_slice(&message[0..48]);

        if G1Affine::from_compressed(&u_point_bytes)
            .is_some()
            .unwrap_u8()
            != 1
        {
            return Err(WedprError::FormatError);
        }
        let u_point: G1Affine =
            G1Affine::from_compressed(&u_point_bytes).unwrap();
        let mut v_point_bytes: [u8; 96] = [0; 96];
        v_point_bytes.copy_from_slice(&message[48..144]);
        println!(
            "v1:{}",
            G2Affine::from_compressed(&v_point_bytes)
                .is_some()
                .unwrap_u8()
        );
        if G2Affine::from_compressed(&v_point_bytes)
            .is_some()
            .unwrap_u8()
            != 1
        {
            return Err(WedprError::FormatError);
        }
        let v_point: G2Affine =
            G2Affine::from_compressed(&v_point_bytes).unwrap();

        Ok(WedprBls128Cipher {
            u_point: G1Projective::from(u_point),
            v_point: G2Projective::from(v_point),
        })
    }
}

fn message_to_g1_point(message: &[u8]) -> G1Projective {
    let domain: &[u8] = b"wedpr-BLS12381G1:SHA-256_";
    let g1_point = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
        &message, domain,
    );
    return g1_point;
}

pub fn encrypt_message(message: &[u8]) -> WedprBls128Cipher {
    let message_g1 = message_to_g1_point(message);
    let rng = rand::rngs::OsRng::default();
    let blinding = Scalar::random(rng);
    let base_g2 = G2Projective::generator();
    let u_point = message_g1 * blinding;
    let v_point = base_g2 * blinding;
    return WedprBls128Cipher { u_point, v_point };
}

pub fn equality_test(
    cipher1: &WedprBls128Cipher,
    cipher2: &WedprBls128Cipher,
) -> bool {
    let pairing1 = pairing(
        &G1Affine::from(cipher1.u_point),
        &G2Affine::from(cipher2.v_point),
    );
    let pairing2 = pairing(
        &G1Affine::from(cipher2.u_point),
        &G2Affine::from(cipher1.v_point),
    );
    return pairing1.eq(&pairing2);
}

#[cfg(test)]
mod tests {
    use crate::*;
    use hex;

    #[test]
    fn test_equality() {
        let message1: &[u8] = b"hello world";
        let message2: &[u8] = b"hello wedpr";
        let cipher1_m1 = encrypt_message(message1);
        let cipher1_m1_bytes = cipher1_m1.to_bytes();
        let cipher1_m1_recover =
            WedprBls128Cipher::from_bytes(&cipher1_m1_bytes).unwrap();
        let cipher2_m1 = encrypt_message(message1);

        let cipher1_m2 = encrypt_message(message2);
        let cipher2_m2 = encrypt_message(message2);

        assert_eq!(equality_test(&cipher1_m1, &cipher2_m1), true);
        assert_eq!(equality_test(&cipher2_m1, &cipher1_m1), true);
        assert_eq!(equality_test(&cipher1_m1_recover, &cipher2_m1), true);

        assert_eq!(equality_test(&cipher1_m2, &cipher2_m2), true);
        assert_eq!(equality_test(&cipher2_m2, &cipher1_m2), true);

        assert_eq!(equality_test(&cipher1_m1, &cipher2_m2), false);
        assert_eq!(equality_test(&cipher2_m2, &cipher1_m1), false);
        assert_eq!(equality_test(&cipher2_m2, &cipher1_m1_recover), false);

        assert_eq!(equality_test(&cipher1_m2, &cipher1_m1), false);
        assert_eq!(equality_test(&cipher1_m1, &cipher1_m2), false);
    }

    #[test]
    fn test_from_web() {
        let message_hello = b"hello";
        let message_wrong = b"wrong";
        let cipher1_hello = encrypt_message(message_hello);
        let cipher1_wrong = encrypt_message(message_wrong);

        let web_hello1 = "912caa3f6fb385af33cc9059ba87523a5ab2ff0112fd21d239ec1ea93a767ae68068a7da29d45dd1665740c32593461f868a81a830ca7db6943dc56512f9507373b35beeec8a4a2f77fe03a72ba6ec0b94bb79de3ff9f24c0bc39e4a75e35c2816c33de0310b2194a48d0eb69cfc86b76e67238a94cea87459c0359451362c8ea6321d9d57dc03d55b219fd20e1188a9";
        let web_bytes1 = hex::decode(web_hello1).unwrap();

        // let web_bytes1 = [178,100,235,129,182,124,252,216,28,9,219,125,168,153,128,192,138,216,173,172,141,46,235,167,172,72,82,241,145,129,208,150,80,80,214,237,229,158,116,93,141,67,101,166,116,228,108,0,175,152,239,234,129,64,178,132,188,240,52,31,118,115,145,215,203,27,19,162,231,180,136,185,63,110,117,174,203,105,51,56,13,138,252,231,179,40,235,128,6,39,120,220,191,62,60,37,16,61,3,197,40,175,205,130,189,125,62,134,80,249,131,21,43,60,171,164,147,6,72,214,246,66,219,97,37,203,31,211,33,202,115,242,164,224,125,110,238,238,95,158,248,74,24,124];
        let web_hello2 = "8fa65c08f9d137934380af14cd659370b8c7e51e8df839f31fb3edaeb50d70a8aed3e7ef441927401e8f40691776292188adecd16201d2f868b2d862771bcb1ade33492db124a4b5329c32ae24971b4980f5649134eb9ac00615286e1dc0b3ae02d27938a92f7a49b9e830fd3857c4c7648f65879a2b018aef26dbfe253ef25e7e7c36dc92d5de4a2fce6e0c4d1c7803";
        let web_bytes2 = hex::decode(web_hello2).unwrap();
        let cipher1_m1_recover =
            WedprBls128Cipher::from_bytes(&web_bytes1).unwrap();
        let cipher2_m1_recover =
            WedprBls128Cipher::from_bytes(&web_bytes2).unwrap();
        // assert_eq!(equality_test(&cipher2_m1_recover, &cipher1_hello), true);

        let web_wrong1 = "ae80d2a0349fac71423365ba24a4ecd195f629e11b3a403de0ba4c81bda121e050508220a50e4da78ff0b4d3c0f4fafcab3c6080b96d3050ec0dcf271e3c00ce81b6e34de2628817a7f9312d4a64bac56207208abc7594c29fb427cd0c0372c80cb4e5e966471dcefedba86857f572554102075f560949b38ba1cb928360b9c865aafaabea691ea2bbc5863775f02f32";
        let web_bytes1_wrong = hex::decode(web_wrong1).unwrap();

        // let web_bytes1 = [178,100,235,129,182,124,252,216,28,9,219,125,168,153,128,192,138,216,173,172,141,46,235,167,172,72,82,241,145,129,208,150,80,80,214,237,229,158,116,93,141,67,101,166,116,228,108,0,175,152,239,234,129,64,178,132,188,240,52,31,118,115,145,215,203,27,19,162,231,180,136,185,63,110,117,174,203,105,51,56,13,138,252,231,179,40,235,128,6,39,120,220,191,62,60,37,16,61,3,197,40,175,205,130,189,125,62,134,80,249,131,21,43,60,171,164,147,6,72,214,246,66,219,97,37,203,31,211,33,202,115,242,164,224,125,110,238,238,95,158,248,74,24,124];
        let web_wrong2 = "80770cfb268456382939b1182f25088c93def05becf439db9c7f1c98628627593ab6b75e6b4f849328bf7aacdd142b7394417f658689838b086fc27a4d649d3c5ec3fbaa9e8fc6de2390e07f8a28bba2308fcf9870e55cd4e723c5ac74202b8213f38e1b950e009894d1334ca47be89d42080aee0b3b942f5a3da3f3e02757b25f9b9ae529d5d1a342df5b708a919ab8";
        let web_bytes2_wrong = hex::decode(web_wrong2).unwrap();
        let cipher1_m2_recover =
            WedprBls128Cipher::from_bytes(&web_bytes1_wrong).unwrap();
        let cipher2_m2_recover =
            WedprBls128Cipher::from_bytes(&web_bytes2_wrong).unwrap();
        // assert_eq!(equality_test(&cipher2_m1_recover, &cipher1_hello), true);


        assert_eq!(equality_test(&cipher1_m1_recover, &cipher2_m1_recover), true);
        assert_eq!(equality_test(&cipher1_m1_recover, &cipher1_hello), true);
        assert_eq!(equality_test(&cipher1_m1_recover, &cipher1_wrong), false);

        assert_eq!(equality_test(&cipher1_m2_recover, &cipher2_m2_recover), true);
        assert_eq!(equality_test(&cipher1_m2_recover, &cipher1_wrong), true);
        assert_eq!(equality_test(&cipher1_m2_recover, &cipher1_hello), false);



    }

}
