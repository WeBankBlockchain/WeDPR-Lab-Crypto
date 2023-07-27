use sha2::Sha512;
// use sha2::Digest;
use rand::rngs::ThreadRng;
// use rand::RngCore;
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    Scalar,
};

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
    let hash_scalar = Scalar::hash_from_bytes::<Sha512>(message);
    let hash_point = EdwardsPoint::mul_base(&hash_scalar);
    return hash_point.compress().to_bytes().to_vec();
}

pub fn scalar_inverse(scalar: &[u8]) -> Vec<u8> {
    // 检查输入切片是否具有正确的大小
    if scalar.len() != SCALAR_SIZE {
        return Vec::new(); // 如果大小不正确，返回空的 Vec<u8>
    }

    // 将输入 &[u8] 转换成 Scalar
    let mut scalar_bytes = [0u8; SCALAR_SIZE];
    scalar_bytes.copy_from_slice(scalar);
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    let inverse_scalar = scalar.invert();
    return inverse_scalar.to_bytes().to_vec();
}

pub fn point_scalar_multi(point: &[u8], scalar: &[u8]) -> Vec<u8> {
    // 检查输入切片是否具有正确的大小
    if point.len() != POINT_SIZE || scalar.len() != SCALAR_SIZE {
        return Vec::new(); // 如果大小不正确，返回空的 Vec<u8>
    }

    // 将输入 &[u8] 转换成 CompressedEdwardsY 表示的点
    let mut point_bytes = [0u8; POINT_SIZE];
    point_bytes.copy_from_slice(point);
    let compressed_point = match CompressedEdwardsY(point_bytes).decompress() {
        Some(point) => point,
        None => return Vec::new(), // 解析点失败，返回空的 Vec<u8>
    };

    // 将输入 &[u8] 转换成 Scalar
    let mut scalar_bytes = [0u8; SCALAR_SIZE];
    scalar_bytes.copy_from_slice(scalar);
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);

    // 执行点乘操作
    let result_point = compressed_point * scalar;

    // 将结果转换成压缩格式的点
    let compressed_result = result_point.compress();

    // 将结果转换成 &[u8]
    compressed_result.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow() {
        // 生成一个随机的标量
        let random_scalar = random_scalar();
        println!("Random Scalar: {:?}", random_scalar);

        // 定义一个消息，对其进行哈希并生成哈希点
        let message = "To really appreciate architecture, you may even need \
                       to commit a murder";
        let hash_point = hash_to_curve(message.as_bytes());

        // 定义一个标量并计算其逆元
        let inverse_scalar = scalar_inverse(&random_scalar);

        // 定义一个点和标量，并进行点乘操作
        let point_mul_result = point_scalar_multi(&hash_point, &random_scalar);
        let point_mul_result2 =
            point_scalar_multi(&point_mul_result, &inverse_scalar);
        assert_eq!(point_mul_result2, hash_point);
    }
}
