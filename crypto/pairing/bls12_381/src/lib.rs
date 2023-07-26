//! This module provides bls12_381 equality test
pub mod peks;

extern crate bls12_381;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use ff::Field;
use rand::{self, Rng};
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
        // println!(
        //     "v1:{}",
        //     G2Affine::from_compressed(&v_point_bytes)
        //         .is_some()
        //         .unwrap_u8()
        // );
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

// fn message_to_g2_point(message: &[u8]) -> G2Projective {
//     let domain: &[u8] = b"wedpr-BLS12381G2:SHA-256_";
//     let g2_point = <G2Projective as
// HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(         &message,
// domain,     );
//     return g2_point;
// }

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
    fn test_from_sdk() {
        let message_hello = b"hello";
        let message_wrong = b"wrong";
        let cipher1_hello = encrypt_message(message_hello);
        let cipher1_wrong = encrypt_message(message_wrong);

        let sdk_hello1 = "a6d13d10c0cce4715d49ed4f0ecf1a4774762f96fa8bce2717be8b4a3f8b50577f71dc8db0143c95f810be0e09b6925e8c391c8008e87d7e227c454d4e961b51755160c473b0dfa191984254650d5d1cc8a79349bf9440ad084ce3deadda6a6217194c54253872d2a08b1dfcd9e01edd2e43a5fe3dd141473262bfc94d46aaf4cb50d1070366563ec7369b3f4e78df45";
        let sdk_bytes1 = hex::decode(sdk_hello1).unwrap();

        // let web_bytes1 =
        // [178,100,235,129,182,124,252,216,28,9,219,125,168,153,128,192,138,
        // 216,173,172,141,46,235,167,172,72,82,241,145,129,208,150,80,80,214,
        // 237,229,158,116,93,141,67,101,166,116,228,108,0,175,152,239,234,129,
        // 64,178,132,188,240,52,31,118,115,145,215,203,27,19,162,231,180,136,
        // 185,63,110,117,174,203,105,51,56,13,138,252,231,179,40,235,128,6,39,
        // 120,220,191,62,60,37,16,61,3,197,40,175,205,130,189,125,62,134,80,
        // 249,131,21,43,60,171,164,147,6,72,214,246,66,219,97,37,203,31,211,33,
        // 202,115,242,164,224,125,110,238,238,95,158,248,74,24,124];
        let sdk_hello2 = "85d07655fa04e21a6a1439f1571deb453fa79f73d46d5662e92c65a046bb62168a3a0e1a65b8e77453887c5239e1005eb99e19294063590976bc65f99e33f3e6b17e9b2c4a80f58c3bfd96ebde66710c76f8b79b522760f50ae312bf973f460c19a76bba34b4a92e5d36dff28300894835e3272c388a6d08d2ea92b94bb5a00808f6a5d013bec61642d8eac1b58303f3";
        let sdk_bytes2 = hex::decode(sdk_hello2).unwrap();
        let cipher1_m1_recover =
            WedprBls128Cipher::from_bytes(&sdk_bytes1).unwrap();
        let cipher2_m1_recover =
            WedprBls128Cipher::from_bytes(&sdk_bytes2).unwrap();
        // assert_eq!(equality_test(&cipher2_m1_recover, &cipher1_hello), true);

        let sdk_wrong1 = "9426437c99f65c8242fa805bd9e38bfa4a0343cc105de36c54793d0e1e318c7eac830b3a7f5ef6bc877c3d358949d63d8d6456544bc019ec9aa5f98deef11b308b4eb19a59942aff977cc5e62e562ae4689a3c0150cf7d5733e9f52d026dd02714bd9e00977e813b3a4783f1bb7dc5acf0c6344b8583006f9f8326add8292a01ae6a385054d65127cd8894f4ed74a618";
        let sdk_bytes1_wrong = hex::decode(sdk_wrong1).unwrap();

        let sdk_wrong2 = "9087ac1f377026c855769bfb9fafb5f28ccdbb01981a5a2da22615dd801cd2e93ed9fc5c0ee39b13fe6721ada3aa19ee86e3446b9acb20ff7e035b3191687ef465cf31e9062f174908007ef6c588e6cee4691861ce4bd64e5b96618dfda4b0d407612abbd841822fb5ba52d4e29639e89074c9442ceba3ea219c001036d91d504cbe24e087a331abd4eb881ad0cd22eb";
        let sdk_bytes2_wrong = hex::decode(sdk_wrong2).unwrap();
        let cipher1_m2_recover =
            WedprBls128Cipher::from_bytes(&sdk_bytes1_wrong).unwrap();
        let cipher2_m2_recover =
            WedprBls128Cipher::from_bytes(&sdk_bytes2_wrong).unwrap();
        // assert_eq!(equality_test(&cipher2_m1_recover, &cipher1_hello), true);

        assert_eq!(
            equality_test(&cipher1_m1_recover, &cipher2_m1_recover),
            true
        );
        assert_eq!(equality_test(&cipher1_m1_recover, &cipher1_hello), true);
        assert_eq!(equality_test(&cipher1_m1_recover, &cipher1_wrong), false);

        assert_eq!(
            equality_test(&cipher1_m2_recover, &cipher2_m2_recover),
            true
        );
        assert_eq!(equality_test(&cipher1_m2_recover, &cipher1_wrong), true);
        assert_eq!(equality_test(&cipher1_m2_recover, &cipher1_hello), false);
    }

    #[test]
    fn test_from_web() {
        let message_hello = b"abc";
        // let message_hello:Vec<u8> = vec![96,97,98,0,0,0,0,0];
        wedpr_println!("message_hello:{:?}", message_hello);
        // let message_wrong = b"wrong";
        let cipher1_hello = encrypt_message(message_hello);
        // let cipher1_wrong = encrypt_message(message_wrong);

        let web_hello1 = "a91c14d9111e95206e5be9e644f68dd6ddb5865da5bfab80d4c7fb7a1a1299db401e200bb401adc87da751283dd8cb2984820a100894e50583daec6261bd8728d6c80689fa02d8f3e7fae23329755229c98456db47f78071e03dd4344e7e8dc3029bf4809a8fc3198dcd4c6810465cbc42fc57329b1d980f70b2a383507c257e35f33f2851e0ab2a40bb24606900c152";
        let web_bytes1 = hex::decode(web_hello1).unwrap();

        // let web_hello2 =
        // "8fa65c08f9d137934380af14cd659370b8c7e51e8df839f31fb3edaeb50d70a8aed3e7ef441927401e8f40691776292188adecd16201d2f868b2d862771bcb1ade33492db124a4b5329c32ae24971b4980f5649134eb9ac00615286e1dc0b3ae02d27938a92f7a49b9e830fd3857c4c7648f65879a2b018aef26dbfe253ef25e7e7c36dc92d5de4a2fce6e0c4d1c7803"
        // ; let web_bytes2 = hex::decode(web_hello2).unwrap();
        // let cipher1_m2_recover = encrypt_message(message_hello);
        let cipher2_m1_recover =
            WedprBls128Cipher::from_bytes(&web_bytes1).unwrap();
        // let cipher2_m1_recover =
        //     WedprBls128Cipher::from_bytes(&web_bytes2).unwrap();
        assert_eq!(equality_test(&cipher2_m1_recover, &cipher1_hello), true);

        // let web_wrong1 =
        // "ae80d2a0349fac71423365ba24a4ecd195f629e11b3a403de0ba4c81bda121e050508220a50e4da78ff0b4d3c0f4fafcab3c6080b96d3050ec0dcf271e3c00ce81b6e34de2628817a7f9312d4a64bac56207208abc7594c29fb427cd0c0372c80cb4e5e966471dcefedba86857f572554102075f560949b38ba1cb928360b9c865aafaabea691ea2bbc5863775f02f32"
        // ; let web_bytes1_wrong = hex::decode(web_wrong1).unwrap();
        //
        //
        // let web_wrong2 =
        // "80770cfb268456382939b1182f25088c93def05becf439db9c7f1c98628627593ab6b75e6b4f849328bf7aacdd142b7394417f658689838b086fc27a4d649d3c5ec3fbaa9e8fc6de2390e07f8a28bba2308fcf9870e55cd4e723c5ac74202b8213f38e1b950e009894d1334ca47be89d42080aee0b3b942f5a3da3f3e02757b25f9b9ae529d5d1a342df5b708a919ab8"
        // ; let web_bytes2_wrong = hex::decode(web_wrong2).unwrap();
        // let cipher1_m2_recover =
        //     WedprBls128Cipher::from_bytes(&web_bytes1_wrong).unwrap();
        // let cipher2_m2_recover =
        //     WedprBls128Cipher::from_bytes(&web_bytes2_wrong).unwrap();
        // // assert_eq!(equality_test(&cipher2_m1_recover, &cipher1_hello),
        // true);
        //
        // assert_eq!(
        //     equality_test(&cipher1_m1_recover, &cipher2_m1_recover),
        //     true
        // );
        // assert_eq!(equality_test(&cipher1_m1_recover, &cipher1_hello), true);
        // assert_eq!(equality_test(&cipher1_m1_recover, &cipher1_wrong),
        // false);
        //
        // assert_eq!(
        //     equality_test(&cipher1_m2_recover, &cipher2_m2_recover),
        //     true
        // );
        // assert_eq!(equality_test(&cipher1_m2_recover, &cipher1_wrong), true);
        // assert_eq!(equality_test(&cipher1_m2_recover, &cipher1_hello),
        // false);
    }

    #[test]
    fn test_from_cpp() {
        let message1 = "8097e7187c6cd863e9f458d5bc320c9ff93a0c830dda517ec915b7deb5c96b9bbab01798226b1c7fa14ad9f455f77f9a851713e3f8211041ca3f905886016b003fa049b97e25e109389a07f95501ede83f9f38eefa174f55383107269cff4c730dbe9a8bdc09a31e847c62d2366f46a042e64c780623c51c9fd9798d731338048576dd3830fdf3dfb4d64eb8f51770c4";
        let message_bytes1 = hex::decode(message1).unwrap();

        // let web_bytes1 =
        // [178,100,235,129,182,124,252,216,28,9,219,125,168,153,128,192,138,
        // 216,173,172,141,46,235,167,172,72,82,241,145,129,208,150,80,80,214,
        // 237,229,158,116,93,141,67,101,166,116,228,108,0,175,152,239,234,129,
        // 64,178,132,188,240,52,31,118,115,145,215,203,27,19,162,231,180,136,
        // 185,63,110,117,174,203,105,51,56,13,138,252,231,179,40,235,128,6,39,
        // 120,220,191,62,60,37,16,61,3,197,40,175,205,130,189,125,62,134,80,
        // 249,131,21,43,60,171,164,147,6,72,214,246,66,219,97,37,203,31,211,33,
        // 202,115,242,164,224,125,110,238,238,95,158,248,74,24,124];
        let message2 = "f097e7187c6cd863e9f458d5bc320c9ff93a0c830dda517ec915b7deb5c96b9bbab01798226b1c7fa14ad9f455f77f9a851713e3f8211041ca3f905886016b003fa049b97e25e109389a07f95501ede83f9f38eefa174f55383107269cff4c730dbe9a8bdc09a31e847c62d2366f46a042e64c780623c51c9fd9798d731338048576dd3830fdf3dfb4d64eb8f51770c4";
        let message2_bytes2 = hex::decode(message2).unwrap();
        let _cipher1_m1_recover =
            WedprBls128Cipher::from_bytes(&message_bytes1).unwrap();
        match WedprBls128Cipher::from_bytes(&message2_bytes2) {
            Ok(_v) => {
                println!("normal happened")
            },
            Err(_) => {
                println!("error happened")
            },
        };
    }
}
