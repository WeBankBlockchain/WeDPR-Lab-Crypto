use curve25519_dalek::{
    ristretto::CompressedRistretto, RistrettoPoint, Scalar,
};
use rand::rngs::ThreadRng;
use sha2::Sha512;

const SCALAR_SIZE: usize = 32;
const POINT_SIZE: usize = 32;

pub fn random_scalar() -> Vec<u8> {
    // 创建一个随机数生成器
    let mut rng: ThreadRng = rand::thread_rng();

    // 生成一个随机的 Scalar
    let scalar = Scalar::random(&mut rng);

    // 将 Scalar 转换成 &[u8]
    scalar.to_bytes().to_vec()
}

pub fn hash_to_curve(message: &[u8]) -> Vec<u8> {
    let hash_point = RistrettoPoint::hash_from_bytes::<Sha512>(message);
    return hash_point.compress().to_bytes().to_vec();
}

pub fn point_scalar_multi(point: &[u8], scalar: &[u8]) -> Vec<u8> {
    // 检查输入切片是否具有正确的大小
    if point.len() != POINT_SIZE || scalar.len() != SCALAR_SIZE {
        return Vec::new(); // 如果大小不正确，返回空的 Vec<u8>
    }

    // 将输入 &[u8] 转换成 CompressedRistretto 表示的点
    let compressed_point = match CompressedRistretto::from_slice(&point) {
        Ok(point) => point,
        Err(_) => return Vec::new(), // 解析点失败，返回空的 Vec<u8>
    };
    let point = match compressed_point.decompress() {
        Some(point) => point,
        None => return Vec::new(), // 解析点失败，返回空的 Vec<u8>
    };

    // 将输入 &[u8] 转换成 Scalar
    let mut scalar_bytes = [0u8; SCALAR_SIZE];
    scalar_bytes.copy_from_slice(scalar);
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);

    // 执行点乘操作
    let result_point = point * scalar;

    // 将结果转换成压缩格式的点
    let compressed_result = result_point.compress();

    // 将结果转换成 &[u8]
    compressed_result.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edwards25519() {
        let message = "hello world".as_bytes();
        // let key = random_scalar();
        let key = [
            125, 185, 175, 119, 127, 247, 65, 76, 146, 163, 142, 178, 247, 149,
            185, 187, 132, 19, 67, 161, 231, 145, 164, 133, 64, 64, 220, 138,
            248, 231, 43, 7,
        ];
        let point = hash_to_curve(&message);
        let result = point_scalar_multi(&point, &key);
        let expected: Vec<u8> = [
            74, 210, 113, 116, 176, 64, 232, 75, 240, 244, 198, 94, 19, 27,
            194, 225, 169, 80, 205, 176, 169, 190, 206, 56, 52, 218, 142, 79,
            28, 132, 70, 16,
        ]
        .to_vec();
        assert_eq!(expected, result);
    }

    #[test]
    fn test_empty_vector() {
        let test_vector: Vec<u8> = Vec::new();
        assert_eq!(test_vector.is_empty(), true);
    }
}
