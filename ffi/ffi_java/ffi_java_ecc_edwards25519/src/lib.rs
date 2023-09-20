extern crate jni;

use ecc_edwards25519::{hash_to_curve, point_scalar_multi, random_scalar};

use jni::{objects::JClass, sys::jbyteArray, JNIEnv};

// 导出函数给JNI接口调用

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_randomScalar(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    // 调用原始函数
    let result = random_scalar();

    // 将 Vec<u8> 转换成 jbyteArray 并返回给Java层
    match env.byte_array_from_slice(&result) {
        Ok(array) => array,
        Err(_) => env.new_byte_array(0).unwrap(), // 返回空的 jbyteArray
    }
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_hashToCurve(
    env: JNIEnv,
    _class: JClass,
    message: jbyteArray,
) -> jbyteArray {
    // 将 jbyteArray 转换成 Vec<u8>
    let message_bytes = match env.convert_byte_array(message) {
        Ok(bytes) => bytes,
        Err(_) => return env.new_byte_array(0).unwrap(), /* 返回空的 jbyteArray */
    };

    // 调用原始函数
    let result = hash_to_curve(&message_bytes);

    // 将 Vec<u8> 转换成 jbyteArray 并返回给Java层
    match env.byte_array_from_slice(&result) {
        Ok(array) => array,
        Err(_) => env.new_byte_array(0).unwrap(), // 返回空的 jbyteArray
    }
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_pointScalarMulti(
    env: JNIEnv,
    _class: JClass,
    point: jbyteArray,
    scalar: jbyteArray,
) -> jbyteArray {
    // 将 jbyteArray 转换成 Vec<u8>
    let point_bytes = match env.convert_byte_array(point) {
        Ok(bytes) => bytes,
        Err(_) => return env.new_byte_array(0).unwrap(), /* 返回空的 jbyteArray */
    };
    let scalar_bytes = match env.convert_byte_array(scalar) {
        Ok(bytes) => bytes,
        Err(_) => return env.new_byte_array(0).unwrap(), /* 返回空的 jbyteArray */
    };

    // 调用原始函数
    let result = point_scalar_multi(&point_bytes, &scalar_bytes);

    // 将 Vec<u8> 转换成 jbyteArray 并返回给Java层
    match env.byte_array_from_slice(&result) {
        Ok(array) => array,
        Err(_) => env.new_byte_array(0).unwrap(), // 返回空的 jbyteArray
    }
}
