use crate::message_to_g1_point;
use bls12_381::{
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use ff::Field;
use rand;
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

    pub fn recover_public_key(pk_bytes: &[u8]) -> Result<G2Projective, WedprError> {
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

    pub fn recover_secret_key(scalar_bytes: &[u8]) -> Result<Scalar, WedprError> {
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

pub fn generate_key() -> PeksKeyPair {
    let rng = rand::rngs::OsRng::default();
    let blinding = Scalar::random(rng);
    let base_g2 = G2Projective::generator();
    let g2_point = base_g2 * blinding;
    return PeksKeyPair {
        pk: g2_point,
        sk: blinding,
    };
}

pub fn encrypt_message(message: &[u8], pk: &G2Projective) -> PeksCipher {
    let message_g1 = message_to_g1_point(message);
    let rng = rand::rngs::OsRng::default();
    let blinding = Scalar::random(rng);
    let base_g2 = G2Projective::generator();
    let g2_point = base_g2 * blinding;

    let pairing_t =
        pairing(&G1Affine::from(message_g1), &G2Affine::from(pk * blinding));
    let sha2_crate = WedprSha2_256::default();
    let c2_vec = sha2_crate.hash(&pairing_t.to_string().as_bytes());
    PeksCipher {
        c1: g2_point,
        c2: c2_vec,
    }
}

pub fn trapdoor(message: &[u8], sk: &Scalar) -> TrapdoorCipher {
    let message_g1 = message_to_g1_point(message);
    let trapdoor_c1 = message_g1 * sk;
    TrapdoorCipher { c1: trapdoor_c1 }
}

pub fn trapdoor_test(
    pkes_cipher: &PeksCipher,
    trapdoor_cipher: &TrapdoorCipher,
) -> bool {
    let pairing_e = pairing(
        &G1Affine::from(trapdoor_cipher.c1),
        &G2Affine::from(pkes_cipher.c1),
    );
    let sha2_crate = WedprSha2_256::default();
    let c_vec = sha2_crate.hash(&pairing_e.to_string().as_bytes());
    c_vec.eq(&pkes_cipher.c2)
}

#[cfg(test)]
mod tests {
    use crate::peks::*;

    #[test]
    fn test_peks() {
        let id1 = "zhangsan".as_bytes();
        let key1 = generate_key();

        let id2 = "李四".as_bytes();
        let key2 = generate_key();

        let id3 = "123456".as_bytes();
        let key3 = generate_key();

        let pk_bytes = key1.get_public_key();

        // let cipher_id1 = encrypt_message(&id1, &key1.pk);
        let cipher_id1 = encrypt_message(&id1, &PeksKeyPair::recover_public_key(&pk_bytes).unwrap());
        let cipher_id2 = encrypt_message(&id2, &key2.pk);
        let cipher_id3 = encrypt_message(&id3, &key3.pk);

        let sk_bytes = key1.get_secret_key();
        // let trapdoor1 = trapdoor(id1, &key1.sk);
        let trapdoor1 = trapdoor(id1, &PeksKeyPair::recover_secret_key(&sk_bytes).unwrap());
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
}
