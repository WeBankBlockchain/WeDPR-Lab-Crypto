use crate::message_to_g1_point;
use bls12_381::{
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use ff::Field;
use rand;
use std::convert::TryInto;
use wedpr_l_crypto_hash_sha2::WedprSha2_256;
use wedpr_l_utils::{error::WedprError, traits::Hash};

#[derive(Clone, Copy, Debug, Default)]
pub struct PeksKeyPair {
    pk: G2Projective,
    sk: Scalar,
}

impl PeksKeyPair {
    pub fn to_bytes(&self) -> Vec<u8> {
        let point_bytes = G2Affine::from(self.pk).to_compressed();
        let result: Vec<u8> =
            [self.sk.to_bytes().as_slice(), point_bytes.as_slice()].concat();
        return result;
    }

    pub fn from_bytes(message: &[u8]) -> Result<PeksKeyPair, WedprError> {
        if message.len() != 128 {
            return Err(WedprError::FormatError);
        }
        let mut sk_bytes: [u8; 32] = [0; 32];
        sk_bytes.copy_from_slice(&message[0..32]);
        let sk = Scalar::from_bytes(&sk_bytes).unwrap_or(Scalar::zero());
        if sk.eq(&Scalar::zero()) {
            return Err(WedprError::FormatError);
        }
        let mut point_bytes: [u8; 96] = [0; 96];
        point_bytes.copy_from_slice(&message[32..128]);
        let pk_affine: G2Affine = G2Affine::from_compressed(&point_bytes)
            .unwrap_or(G2Affine::default());
        if pk_affine.eq(&G2Affine::default()) {
            return Err(WedprError::FormatError);
        }
        let pk = G2Projective::from(&pk_affine);
        Ok(PeksKeyPair { pk, sk })
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        G2Affine::from(self.pk).to_compressed().to_vec()
    }

    pub fn recover_public_key(
        pk_bytes: &[u8],
    ) -> Result<G2Projective, WedprError> {
        if pk_bytes.len() != 96 {
            return Err(WedprError::FormatError);
        }
        let mut point_bytes: [u8; 96] = [0; 96];
        point_bytes.copy_from_slice(&pk_bytes);
        let pk_affine: G2Affine = G2Affine::from_compressed(&point_bytes)
            .unwrap_or(G2Affine::default());
        if pk_affine.eq(&G2Affine::default()) {
            return Err(WedprError::FormatError);
        }
        Ok(G2Projective::from(&pk_affine))
    }

    pub fn get_secret_key(&self) -> Vec<u8> {
        self.sk.to_bytes().to_vec()
    }

    pub fn recover_secret_key(
        scalar_bytes: &[u8],
    ) -> Result<Scalar, WedprError> {
        if scalar_bytes.len() != 32 {
            return Err(WedprError::FormatError);
        }
        let mut sk_bytes: [u8; 32] = [0; 32];
        sk_bytes.copy_from_slice(&scalar_bytes);
        let sk = Scalar::from_bytes(&sk_bytes).unwrap_or(Scalar::zero());
        if sk.eq(&Scalar::zero()) {
            return Err(WedprError::FormatError);
        }
        Ok(sk)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PeksCipher {
    c1: G2Projective,
    c2: Vec<u8>,
}

impl PeksCipher {
    pub fn to_bytes(&self) -> Vec<u8> {
        let point_bytes = G2Affine::from(self.c1).to_compressed();
        let result: Vec<u8> =
            [point_bytes.as_slice(), self.c2.as_slice()].concat();
        return result;
    }

    pub fn from_bytes(message: &[u8]) -> Result<PeksCipher, WedprError> {
        if message.len() != 128 {
            return Err(WedprError::FormatError);
        }
        let mut point_bytes: [u8; 96] = [0; 96];
        point_bytes.copy_from_slice(&message[0..96]);
        let c1_affine: G2Affine = G2Affine::from_compressed(&point_bytes)
            .unwrap_or(G2Affine::default());
        if c1_affine.eq(&G2Affine::default()) {
            return Err(WedprError::FormatError);
        }
        let c1 = G2Projective::from(&c1_affine);
        let mut c2_bytes: [u8; 32] = [0; 32];
        c2_bytes.copy_from_slice(&message[96..128]);
        let c2 = c2_bytes.to_vec();
        Ok(PeksCipher { c1, c2 })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TrapdoorCipher {
    c1: G1Projective,
}

impl TrapdoorCipher {
    pub fn to_bytes(&self) -> Vec<u8> {
        let point_bytes = G1Affine::from(self.c1).to_compressed();
        let result: Vec<u8> = point_bytes.to_vec();
        return result;
    }

    pub fn from_bytes(message: &[u8]) -> Result<TrapdoorCipher, WedprError> {
        if message.len() != 48 {
            return Err(WedprError::FormatError);
        }
        let mut point_bytes: [u8; 48] = [0; 48];
        point_bytes.copy_from_slice(&message[0..48]);
        let c1_affine: G1Affine = G1Affine::from_compressed(&point_bytes)
            .unwrap_or(G1Affine::default());
        if c1_affine.eq(&G1Affine::default()) {
            return Err(WedprError::FormatError);
        }
        let c1 = G1Projective::from(&c1_affine);

        Ok(TrapdoorCipher { c1 })
    }
}

pub fn seed_to_scalar(seed: &[u8]) -> Result<Scalar, WedprError> {
    let seed_vec = seed.to_vec();
    if seed_vec.len() != 32 {
        return Err(WedprError::FormatError);
    }
    let seed_array: [u8; 32] = match seed_vec.try_into() {
        Ok(v) => v,
        Err(_) => return Err(WedprError::FormatError),
    };
    let result = Scalar::from_bytes(&seed_array).unwrap_or(Scalar::zero());
    if result.eq(&Scalar::zero()) {
        return Err(WedprError::FormatError);
    }
    Ok(result)
}
pub fn generate_key_with_seed(seed: &[u8]) -> Result<PeksKeyPair, WedprError> {
    let blinding = seed_to_scalar(seed)?;
    let base_g2 = G2Projective::generator();
    let g2_point = base_g2 * blinding;
    return Ok(PeksKeyPair {
        pk: g2_point,
        sk: blinding,
    });
}

pub fn generate_key() -> PeksKeyPair {
    let rng = rand::rngs::OsRng::default();
    let blinding = Scalar::random(rng).to_bytes();
    generate_key_with_seed(&blinding).unwrap()
}

pub fn encrypt_message(message: &[u8], pk: &G2Projective) -> PeksCipher {
    let rng = rand::rngs::OsRng::default();
    let blinding = Scalar::random(rng).to_bytes();
    encrypt_message_with_seed(&blinding, message, pk).unwrap()
}

pub fn encrypt_message_with_seed(
    seed: &[u8],
    message: &[u8],
    pk: &G2Projective,
) -> Result<PeksCipher, WedprError> {
    let blinding = seed_to_scalar(seed)?;

    let message_g1 = message_to_g1_point(message);

    let base_g2 = G2Projective::generator();
    let g2_point = base_g2 * blinding;

    let pairing_t =
        pairing(&G1Affine::from(message_g1), &G2Affine::from(pk * blinding));
    let sha2_crate = WedprSha2_256::default();
    let c2_vec = sha2_crate.hash(&pairing_t.to_string().as_bytes());
    Ok(PeksCipher {
        c1: g2_point,
        c2: c2_vec,
    })
}

pub fn trapdoor(message: &[u8], sk: &Scalar) -> TrapdoorCipher {
    let message_g1 = message_to_g1_point(message);
    let trapdoor_c1 = message_g1 * sk;
    TrapdoorCipher { c1: trapdoor_c1 }
}

pub fn trapdoor_test(
    peks_cipher: &PeksCipher,
    trapdoor_cipher: &TrapdoorCipher,
) -> bool {
    let pairing_e = pairing(
        &G1Affine::from(trapdoor_cipher.c1),
        &G2Affine::from(peks_cipher.c1),
    );
    let sha2_crate = WedprSha2_256::default();
    let c_vec = sha2_crate.hash(&pairing_e.to_string().as_bytes());
    c_vec.eq(&peks_cipher.c2)
}

#[cfg(test)]
mod tests {
    use crate::peks::*;
    use wedpr_l_common_coder_base64::WedprBase64;
    use wedpr_l_utils::traits::Coder;

    #[test]
    fn test_complex_word() {
        let id1 = hex::decode("f0a59684f0acba93").unwrap();
        let key1 = generate_key();
        let cipher_id1 = encrypt_message(&id1, &key1.pk);
        let trapdoor1 = trapdoor(&id1, &key1.sk);
        assert_eq!(trapdoor_test(&cipher_id1, &trapdoor1), true);
    }

    #[test]
    fn test_peks() {
        let id1 = "zhangsan".as_bytes();
        let key1 = generate_key();
        wedpr_println!("key1:{:?}", key1.to_bytes());
        wedpr_println!("key1_length:{:?}", key1.to_bytes().len());

        let id2 = "李四".as_bytes();
        let key2 = generate_key();

        let id3 = "123456".as_bytes();
        let key3 = generate_key();

        let pk_bytes = key1.get_public_key();

        // let cipher_id1 = encrypt_message(&id1, &key1.pk);
        let cipher_id1 = encrypt_message(
            &id1,
            &PeksKeyPair::recover_public_key(&pk_bytes).unwrap(),
        );
        let cipher_id2 = encrypt_message(&id2, &key2.pk);
        let cipher_id3 = encrypt_message(&id3, &key3.pk);

        // let cipher_id1 = encrypt_message(&vec![1, 2, 3, 4],
        // &PeksKeyPair::recover_public_key(&pk_bytes).unwrap());
        // wedpr_println!("cipher_id1:{:?}", cipher_id1.to_bytes());

        let sk_bytes = key1.get_secret_key();
        // let trapdoor1 = trapdoor(id1, &key1.sk);
        let trapdoor1 =
            trapdoor(id1, &PeksKeyPair::recover_secret_key(&sk_bytes).unwrap());
        assert_eq!(trapdoor_test(&cipher_id1, &trapdoor1), true);
        assert_eq!(trapdoor_test(&cipher_id2, &trapdoor1), false);
        assert_eq!(trapdoor_test(&cipher_id3, &trapdoor1), false);

        let trapdoor2 = trapdoor(id2, &key2.sk);
        assert_eq!(trapdoor_test(&cipher_id1, &trapdoor2), false);
        assert_eq!(trapdoor_test(&cipher_id2, &trapdoor2), true);
        assert_eq!(trapdoor_test(&cipher_id3, &trapdoor2), false);

        let trapdoor2_false = trapdoor(id2, &key1.sk);
        assert_eq!(trapdoor_test(&cipher_id1, &trapdoor2_false), false);
        assert_eq!(trapdoor_test(&cipher_id2, &trapdoor2_false), false);
        assert_eq!(trapdoor_test(&cipher_id3, &trapdoor2_false), false);

        let cipher_id1_bytes = cipher_id1.to_bytes();
        let cipher_id1_recover =
            PeksCipher::from_bytes(&cipher_id1_bytes).unwrap();
        let trapdoor1_bytes = trapdoor1.to_bytes();
        let trapdoor1_recover =
            TrapdoorCipher::from_bytes(&trapdoor1_bytes).unwrap();
        assert_eq!(
            trapdoor_test(&cipher_id1_recover, &trapdoor1_recover),
            true
        );
        assert_eq!(trapdoor_test(&cipher_id1_recover, &trapdoor2), false);
        assert_eq!(trapdoor_test(&cipher_id1_recover, &trapdoor1), true);
        assert_eq!(trapdoor_test(&cipher_id1, &trapdoor1_recover), true);
    }

    #[test]
    fn test_from_web() {
        let message_hello = hex::decode("01020304").unwrap();
        let message_wrong = hex::decode("04030201").unwrap();

        let seed = hex::decode(
            "0195f7500b825a152a42ed730df86de0331ee7b2579c944ee68f682a84e6004d",
        )
        .unwrap();

        let cipher_message_str = "87af4f84f5cabefe4e4e52a98735a4aa7ac39ad56ca14f2d1fef6aea07dae2c42e948df92465940057329e241c13aa3213941282526cc735e6926fc9c4044b1a733e11c82fffcf4f516a9a3fb32dbafac76446270226e96f4a9a6d2537a68e4f2bdca94fd6d2ad2904196174ccb66a5cec3135f1b6310c942bfccae5a4386d34";
        let cipher_message_bytes = hex::decode(cipher_message_str).unwrap();
        let cipher_message =
            PeksCipher::from_bytes(&cipher_message_bytes).unwrap();

        let key1 = generate_key_with_seed(&seed).unwrap();
        let cipher_message_test =
            encrypt_message_with_seed(&seed, &message_hello, &key1.pk).unwrap();
        // wedpr_println!("cipher_message_test:{:?}",
        // cipher_message_test.to_bytes()); wedpr_println!("
        // cipher_message_bytes:{:?}", cipher_message_bytes);

        let trapdoor1 = trapdoor(&message_hello, &key1.sk);
        let trapdoor2 = trapdoor(&message_wrong, &key1.sk);

        assert_eq!(trapdoor_test(&cipher_message, &trapdoor1), true);

        assert_eq!(trapdoor_test(&cipher_message, &trapdoor2), false);
    }

    #[test]
    fn test_base64_decode() {
        let base64_pk = "ifC8LWz8S67q2zmg4Jnt9RoPtjj4HPBq2Ga47aQlSGdz+V3ySo6yQiMSvpOUudZ2Brv8u4rViiFfC7yroiFNcVAvFf/f6ftcqDZQiRodvDqJG5KqlYa8IJHzxm00ZW5I";
        let base64 = WedprBase64::default();
        let pk_bytes = base64.decode(base64_pk).unwrap();
        // wedpr_println!("pk_bytes:{:?}", pk_bytes);
        let pk = PeksKeyPair::recover_public_key(&pk_bytes).unwrap();
        // wedpr_println!("pk_bytes:{:?}", pk_bytes);
        let message_hello = hex::decode("01020304").unwrap();
        let cipher = encrypt_message(&message_hello, &pk);
        // wedpr_println!("cipher:{:?}", cipher.to_bytes());

        let pk_b: Vec<u8> = vec![
            166, 128, 102, 24, 26, 188, 251, 191, 70, 187, 221, 154, 94, 222,
            132, 98, 247, 202, 88, 211, 23, 95, 6, 11, 218, 184, 14, 25, 137,
            212, 231, 234, 79, 132, 33, 142, 12, 108, 128, 138, 42, 28, 32, 95,
            28, 37, 192, 237, 9, 123, 245, 203, 141, 103, 203, 241, 14, 187,
            150, 79, 172, 21, 11, 7, 250, 94, 86, 143, 233, 96, 246, 10, 133,
            71, 226, 121, 202, 80, 119, 56, 95, 88, 23, 221, 119, 131, 109,
            120, 55, 99, 132, 208, 237, 115, 51, 179,
        ];
        let seed_b: Vec<u8> = vec![
            1, 90, 160, 40, 152, 38, 133, 69, 16, 19, 78, 178, 73, 141, 154,
            223, 51, 220, 69, 67, 206, 170, 49, 27, 74, 232, 77, 229, 212, 234,
            4, 105,
        ];
        let pk_b_new = PeksKeyPair::recover_public_key(&pk_b).unwrap();
        let cipher_new =
            encrypt_message_with_seed(&seed_b, &message_hello, &pk_b_new)
                .unwrap();
        // wedpr_println!("cipher_new:{:?}", cipher_new.to_bytes());

        // assert_eq!(pk_bytes, pk.to_bytes());
    }
}
