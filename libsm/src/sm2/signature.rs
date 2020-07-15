// Copyright 2018 Cryptape Technology LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::ecc::*;
use super::field::FieldElem;
use num_bigint::BigUint;
use num_traits::*;
use sm3::hash::Sm3Hash;

use yasna;

use byteorder::{BigEndian, WriteBytesExt};

pub type Pubkey = Point;
pub type Seckey = BigUint;

#[derive(Clone, Debug)]
pub struct Signature {
    r: BigUint,
    s: BigUint,
}

impl Signature {
    pub fn new(r_bytes: &[u8], s_bytes: &[u8]) -> Self {
        let r = BigUint::from_bytes_be(r_bytes);
        let s = BigUint::from_bytes_be(s_bytes);
        Signature { r, s }
    }

    pub fn hex_encode(self) -> (String, String) {
        let mut r = hex::encode(self.r.to_bytes_be());
        if r.len() != 64 {
            if r.len() == 62 {
                r = "00".to_string() + &r;
            }
        }
        let mut s = hex::encode(self.s.to_bytes_be());
        if s.len() != 64 {
            if s.len() == 62 {
                s = "00".to_string() + &s;
            }
        }
        (r, s)
    }

    pub fn hex_decode(r: String, s: String) -> Result<Signature, hex::FromHexError> {
        let r = BigUint::from_bytes_be(&hex::decode(r)?);
        // println!("r.length = {}", r.length());
        let s = BigUint::from_bytes_be(&hex::decode(s)?);
        // println!("s.length = {}", s.length());
        Ok(Signature {r, s})
    }

    pub fn der_decode(buf: &[u8]) -> Result<Signature, yasna::ASN1Error> {
        let (r, s) = yasna::parse_der(buf, |reader| {
            reader.read_sequence(|reader| {
                let r = reader.next().read_biguint()?;
                let s = reader.next().read_biguint()?;
                Ok((r, s))
            })
        })?;
        Ok(Signature { r, s })
    }

    pub fn der_decode_raw(buf: &[u8]) -> Result<Signature, ()> {
        if buf[0] != 0x02 {
            return Err(());
        }
        let r_len: usize = buf[1] as usize;
        if buf.len() <= r_len + 4 {
            return Err(());
        }
        let r = BigUint::from_bytes_be(&buf[2..2 + r_len]);

        let buf = &buf[2 + r_len..];
        if buf[0] != 0x02 {
            return Err(());
        }
        let s_len: usize = buf[1] as usize;
        if buf.len() < s_len + 2 {
            return Err(());
        }
        let s = BigUint::from_bytes_be(&buf[2..2 + s_len]);

        Ok(Signature { r, s })
    }

    pub fn der_encode(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_biguint(&self.r);
                writer.next().write_biguint(&self.s);
            })
        })
    }

    #[inline]
    pub fn get_r(&self) -> &BigUint {
        &self.r
    }

    #[inline]
    pub fn get_s(&self) -> &BigUint {
        &self.s
    }
}

pub struct SigCtx {
    curve: EccCtx,
}

impl SigCtx {
    pub fn new() -> SigCtx {
        SigCtx {
            curve: EccCtx::new(),
        }
    }

    pub fn hash(&self, id: &str, pk: &Point, msg: &[u8]) -> [u8; 32] {
        let curve = &self.curve;

        let mut prepend: Vec<u8> = Vec::new();
        if id.len() * 8 > 65535 {
            panic!("ID is too long.");
        }
        prepend
            .write_u16::<BigEndian>((id.len() * 8) as u16)
            .unwrap();
        for c in id.bytes() {
            prepend.push(c);
        }

        let mut a = curve.get_a().to_bytes();
        let mut b = curve.get_b().to_bytes();

        prepend.append(&mut a);
        prepend.append(&mut b);

        let (x_g, y_g) = curve.to_affine(&curve.generator());
        let (mut x_g, mut y_g) = (x_g.to_bytes(), y_g.to_bytes());
        prepend.append(&mut x_g);
        prepend.append(&mut y_g);

        let (x_a, y_a) = curve.to_affine(pk);
        let (mut x_a, mut y_a) = (x_a.to_bytes(), y_a.to_bytes());
        prepend.append(&mut x_a);
        prepend.append(&mut y_a);

        let mut hasher = Sm3Hash::new(&prepend[..]);
        let z_a = hasher.get_hash();

        // Z_A = HASH_256(ID_LEN || ID || x_G || y_G || x_A || y_A)

        // e = HASH_256(Z_A || M)

        let mut prepended_msg: Vec<u8> = Vec::new();
        prepended_msg.extend_from_slice(&z_a[..]);
        prepended_msg.extend_from_slice(&msg[..]);

        let mut hasher = Sm3Hash::new(&prepended_msg[..]);
        hasher.get_hash()
    }

    pub fn sign(&self, msg: &[u8], sk: &BigUint, pk: &Point) -> Signature {
        // Get the value "e", which is the hash of message and ID, EC parameters and public key
       let digest = self.hash("1234567812345678", pk, msg);
        // let digest = self.hash("31323334353637383132333435363738", pk, msg);

        self.sign_raw(&digest[..], sk)
    }

    pub fn sign_raw(&self, digest: &[u8], sk: &BigUint) -> Signature {
        let curve = &self.curve;
        // Get the value "e", which is the hash of message and ID, EC parameters and public key

        let e = BigUint::from_bytes_be(digest);

        // two while loops
        loop {
            // k = rand()
            // (x_1, y_1) = g^kg
            let k = self.curve.random_uint();
            let p_1 = curve.g_mul(&k);
            let (x_1, _) = curve.to_affine(&p_1);
            let x_1 = x_1.to_biguint();

            // r = e + x_1
            let r = (&e + x_1) % curve.get_n();
            if r == BigUint::zero() || &r + &k == *curve.get_n() {
                continue;
            }

            // s = (1 + sk)^-1 * (k - r * sk)
            let s1 = curve.inv_n(&(sk + BigUint::one()));

            let mut s2_1 = &r * sk;
            if s2_1 < k {
                s2_1 += curve.get_n();
            }
            let mut s2 = s2_1 - k;
            s2 %= curve.get_n();
            let s2 = curve.get_n() - s2;

            let s = (s1 * s2) % curve.get_n();

            if s != BigUint::zero() {
                // Output the signature (r, s)
                return Signature { r, s };
            }
            panic!("cannot sign")
        }
    }

    pub fn verify(&self, msg: &[u8], pk: &Point, sig: &Signature) -> bool {
        //Get hash value
       let digest = self.hash("1234567812345678", pk, msg);
        // let digest = self.hash("31323334353637383132333435363738", pk, msg);
        //println!("digest: {:?}", digest);
        self.verify_raw(&digest[..], pk, sig)
    }

    pub fn verify_raw(&self, digest: &[u8], pk: &Point, sig: &Signature) -> bool {
        if digest.len() != 32 {
            panic!("the length of digest must be 32-bytes.");
        }
        let e = BigUint::from_bytes_be(digest);

        let curve = &self.curve;
        // check r and s
        if *sig.get_r() == BigUint::zero() || *sig.get_s() == BigUint::zero() {
            return false;
        }
        if *sig.get_r() >= *curve.get_n() || *sig.get_s() >= *curve.get_n() {
            return false;
        }

        // calculate R
        let t = (sig.get_s() + sig.get_r()) % curve.get_n();
        if t == BigUint::zero() {
            return false;
        }

        let p_1 = curve.add(&curve.g_mul(sig.get_s()), &curve.mul(&t, pk));
        let (x_1, _) = curve.to_affine(&p_1);
        let x_1 = x_1.to_biguint();

        let r_ = (e + x_1) % curve.get_n();

        // check R == r?
        r_ == *sig.get_r()
    }

    pub fn new_keypair(&self) -> (Point, BigUint) {
        let curve = &self.curve;
        let mut sk: BigUint = curve.random_uint();
        let mut pk: Point = curve.g_mul(&sk);

        loop {
            if !pk.is_zero() {
                break;
            }
            sk = curve.random_uint();
            pk = curve.g_mul(&sk);
        }

        (pk, sk)
    }

    pub fn pk_from_sk(&self, sk: &BigUint) -> Point {
        let curve = &self.curve;
        if *sk >= *curve.get_n() || *sk == BigUint::zero() {
            panic!("invalid seckey");
        }
        curve.mul(&sk, &curve.generator())
    }

    pub fn load_pubkey(&self, buf: &[u8]) -> Result<Point, ()> {
        self.curve.bytes_to_point(buf)
    }

    pub fn serialize_pubkey(&self, p: &Point, compress: bool) -> Vec<u8> {
        self.curve.point_to_bytes(p, compress)
    }

    pub fn load_seckey(&self, buf: &[u8]) -> Result<BigUint, ()> {
        if buf.len() != 32 {
            return Err(());
        }
        let sk = BigUint::from_bytes_be(buf);
        if sk > *self.curve.get_n() {
            Err(())
        } else {
            Ok(sk)
        }
    }

    pub fn serialize_seckey(&self, x: &BigUint) -> Vec<u8> {
        if *x > *self.curve.get_n() {
            panic!("invalid secret key");
        }
        let x = FieldElem::from_biguint(x);
        x.to_bytes()
    }
}

impl Default for SigCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm2_for_dxct() {
        let ctx = SigCtx::new();
        let private_key_vec = hex::decode("D96C222D8602B287973E2ACA7E3FEDADFD0BD67F2914D3E16F46FAB8A8506F2B").unwrap();
        let new_sk = ctx.load_seckey(&private_key_vec[..]).unwrap();
        let pk = ctx.pk_from_sk(&new_sk);
        let pk_raw = ctx.serialize_pubkey(&pk, false);
        let pk_str = hex::encode(pk_raw);
        assert_eq!(&pk_str, "04faa556408d8dbfbe6167a15869e7b4c48bf04f5ee724faa640bab1d0b9eb86f3b2c3cdb628da1144fc67d2f7b25a42906dc5b5f337c01ed89be635f211f58d27");
        let msg = hex::decode("00").unwrap();
        let signature = ctx.sign(&msg, &new_sk, &pk);
        println!("signature = {:?}", signature.hex_encode());
    }

    #[test]
    fn test_sign_and_verify() {
        let string = String::from("2daef60e7a0b8f5e024c81cd2ab3109f2b4f155cf83adeb2ae5532f74a157fdf");
        let msg = hex::decode(string).unwrap();


        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair();
        let pk_raw = ctx.serialize_pubkey(&pk, false);
        println!("pk = {}", hex::encode(pk_raw));

        let signature = ctx.sign(&msg, &sk, &pk);
        let (r, s) = signature.hex_encode();
        println!("sig_hex r = {}, s = {}", r, s);
        let sig_decode = Signature::hex_decode(r, s);
        println!("sig_decode = {:?}", sig_decode);

//        assert!(ctx.verify(&msg, &pk, &signature));
    }
    #[test]
    fn test_sig_encode_and_decode() {
        let string = String::from("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let msg = string.as_bytes();

        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair();

        let signature = ctx.sign(msg, &sk, &pk);
        let der = signature.der_encode();
        let sig = Signature::der_decode(&der[..]).unwrap();
        assert!(ctx.verify(msg, &pk, &sig));

        let signature = ctx.sign(msg, &sk, &pk);
        let der = signature.der_encode();
        let sig = Signature::der_decode_raw(&der[2..]).unwrap();
        assert!(ctx.verify(msg, &pk, &sig));
    }

    #[test]
    fn test_key_serialization() {
        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair();

        let pk_v = ctx.serialize_pubkey(&pk, true);
        let new_pk = ctx.load_pubkey(&pk_v[..]).unwrap();
        assert!(ctx.curve.eq(&new_pk, &pk));

        let sk_v = ctx.serialize_seckey(&sk);
        let new_sk = ctx.load_seckey(&sk_v[..]).unwrap();
        assert_eq!(new_sk, sk);
    }

    #[test]
    fn test_gmssl() {
        let msg: &[u8] = &[
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0,
        ];
        println!("msg = {}", hex::encode(msg));


        let pk: &[u8] = &[
            4, 233, 185, 71, 125, 111, 174, 63, 105, 217, 19, 218, 72, 114, 185, 96, 243, 176, 1,
            8, 239, 132, 114, 119, 216, 38, 21, 117, 142, 223, 42, 157, 170, 123, 219, 65, 50, 238,
            191, 116, 238, 240, 197, 158, 1, 145, 177, 107, 112, 91, 101, 86, 50, 204, 218, 254,
            172, 2, 250, 33, 56, 176, 121, 16, 215,
        ];
        println!("pk = {}", hex::encode(pk));


        let sig: &[u8] = &[
            48, 69, 2, 33, 0, 171, 111, 172, 181, 242, 159, 198, 106, 33, 229, 104, 147, 245, 97,
            132, 141, 141, 17, 27, 97, 156, 159, 160, 188, 239, 78, 124, 17, 211, 124, 113, 26, 2,
            32, 53, 21, 4, 195, 198, 42, 71, 17, 110, 157, 113, 185, 178, 74, 147, 87, 129, 179,
            168, 163, 171, 126, 39, 156, 198, 29, 163, 199, 82, 25, 13, 112,
        ];

        let curve = EccCtx::new();
        let ctx = SigCtx::new();


        let pk = curve.bytes_to_point(&pk).unwrap();

        let sig = Signature::der_decode(&sig).unwrap();
        println!("sig = {:?}", sig);
        assert!(ctx.verify_raw(msg, &pk, &sig));

        let (r, s) = sig.hex_encode();
        println!("sig_hex r = {}, s = {}", r, s);
        let sig_decode = Signature::hex_decode(r, s).unwrap();
        println!("sig_decode = {:?}", sig_decode);
        println!("{}", ctx.verify_raw(msg, &pk, &sig_decode));

       let r = BigUint::from_bytes_be(&hex::decode("FA30BA6D44A9CA88FDBA5EF153C86605DAB9C24B44E1804FC802E73B81D04FE9").unwrap());
       let s = BigUint::from_bytes_be(&hex::decode("B09D1335ED0CA9A3ECF20607789FC1DD9EBA5ECF5C65F7C916863629336794D4").unwrap());
       let signature = Signature{r, s};
       println!("signature = {:?}", signature);
       let pk_test = hex::decode("04FAA556408D8DBFBE6167A15869E7B4C48BF04F5EE724FAA640BAB1D0B9EB86F3B2C3CDB628DA1144FC67D2F7B25A42906DC5B5F337C01ED89BE635F211F58D27").unwrap();
       let pk = curve.bytes_to_point(&pk_test).unwrap();
       let msg = hex::decode("44DB476208775A0E5DBD7C00D08833A7083E232DFA95788E2EC7CC231772C23A").unwrap();
       println!("ctx.verify(&msg, &pk, &sig) = {:?}", ctx.verify(&msg, &pk, &signature));

       let r = BigUint::from_bytes_be(&hex::decode("7dc3cc3fd443ff142b9ca42aa08a1df4a2e841416cd24eb6b7c6aad24b08bcfc").unwrap());
       let s = BigUint::from_bytes_be(&hex::decode("decdf285cb16bf3e5cd02eeeaf99a95835721b837b359df1173289caee260be8").unwrap());
       let signature = Signature{r, s};
       println!("signature = {:?}", signature);
       let pk_test = hex::decode("04f16305eee0f82ca4cf8532d48f42a6dc87f6f37d39481cd15d6b318fa6e778a85fbf09583ef46b0418810466a6ec5559cca7af2f772caca351a345a153157ee8").unwrap();
       let pk = curve.bytes_to_point(&pk_test).unwrap();
       let msg = hex::decode("2daef60e7a0b8f5e024c81cd2ab3109f2b4f155cf83adeb2ae5532f74a157fdf").unwrap();
       println!("ctx.verify(&msg, &pk, &sig) = {:?}", ctx.verify(&msg, &pk, &signature));

    //    let r = BigUint::from_bytes_be(&hex::decode("84DB051DE095DE8DB339911F5EDEF2908B892451C4C3C0B78B157A436E2C3891").unwrap());
    //    let s = BigUint::from_bytes_be(&hex::decode("8BE4754C25EE77BA5F6401FE8C283CD7BB0021748DD055792C59AB6221D9E9A4").unwrap());
    //    let signature = Signature{r, s};
    //    println!("signature = {:?}", signature);
    //    let pk_test = hex::decode("04FAA556408D8DBFBE6167A15869E7B4C48BF04F5EE724FAA640BAB1D0B9EB86F3B2C3CDB628DA1144FC67D2F7B25A42906DC5B5F337C01ED89BE635F211F58D27").unwrap();
    //    let pk = curve.bytes_to_point(&pk_test).unwrap();
    //    let msg = hex::decode("00").unwrap();
    //    println!("ctx.verify(&msg, &pk, &sig) = {:?}", ctx.verify(&msg, &pk, &sig));

    //    let r = BigUint::from_bytes_be(&hex::decode("AEC627694305D4334163B7EC7C2B2C8FB5BC416DEA0220094A1E08B546D793D0").unwrap());
    //    let s = BigUint::from_bytes_be(&hex::decode("3BA3AE45CC5543FBF9154C1DDEDA922BBD77D39E78CA997225D29098560F0E47").unwrap());
    //    let signature = Signature{r, s};
    //    println!("signature = {:?}", signature);
    //    let pk_test = hex::decode("04A62178C87DE5B396A6655DD26A0A87AE6B5EA7E0DA44C4E11F3BED7F0C13E970B1683C48344BB65A5132ABDF728D7546289858AAF5049B70E280B429168B5553").unwrap();
    //    let pk = curve.bytes_to_point(&pk_test).unwrap();
    //    let msg = hex::decode("754C37FA4AA3FC278FA65007A40FF10FF991556625DBA8B4B44133D9C44A5AC6").unwrap();
    //    println!("ctx.verify(&msg, &pk, &sig) = {:?}", ctx.verify(&msg, &pk, &sig));

    //    let r = BigUint::from_bytes_be(&hex::decode("13B0E1C21FBBBA309C144ABFFC55455BC729BEB1505468F7E3FD7548568B0C6D").unwrap());
    //    let s = BigUint::from_bytes_be(&hex::decode("50CA851C1488941D4AF0AFF0BADCBB8F4EEECC084DC5EF44B62BCCDCBA7B467B").unwrap());
    //    let signature = Signature{r, s};
    //    println!("signature = {:?}", signature);
    //    let pk_test = hex::decode("04C6C83E3FD3CFE6509554711F68B0503612ABC45ADE80E2C9E22B39D475DAE9FCABF8C0EA1A491805A595AFF627916CEBA627B4A2DD1353DF844D648829498A09").unwrap();
    //    let pk = curve.bytes_to_point(&pk_test).unwrap();
    //    let msg = hex::decode("85B013F60835FE86D9D88E59EB99F4A6B0144307FB29810098320FA21455818D").unwrap();
    //    println!("ctx.verify(&msg, &pk, &sig) = {:?}", ctx.verify_raw(&msg, &pk, &sig));

    //    let r = BigUint::from_bytes_be(&hex::decode("cb112baccd0a9de9760886dc7438992c05249edbd97524999a2f10b61ebde826").unwrap());
    //    let s = BigUint::from_bytes_be(&hex::decode("14d290a701b029a8d33ea57af91c22f3db699fbfb7d7ac3f4a763ecf51563605").unwrap());
    //    let signature = Signature{r, s};
    //    println!("signature = {:?}", signature);
    //    let pk_test = hex::decode("04f16305eee0f82ca4cf8532d48f42a6dc87f6f37d39481cd15d6b318fa6e778a85fbf09583ef46b0418810466a6ec5559cca7af2f772caca351a345a153157ee8").unwrap();
    //    let pk = curve.bytes_to_point(&pk_test).unwrap();
    //    let msg = hex::decode("2daef60e7a0b8f5e024c81cd2ab3109f2b4f155cf83adeb2ae5532f74a157fdf").unwrap();
    //    println!("ctx.verify(&msg, &pk, &sig) = {:?}", ctx.verify(&msg, &pk, &sig));

    }
}
