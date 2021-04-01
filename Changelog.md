**WeDPR-Lab-Crypto v1.1.0版本**开源主要内容如下：
- **核心密码算法组件**，包括：

  -  分组加密算法：包括AES-256、国密SM4；
  -  哈希算法：包括SHA3、BLAKE2、RIPEMD-160；
  -  椭圆曲线计算：包括椭圆曲线BN128的点加、点乘及双线性对操作； 
  -  数字签名算法：包括Ed25519；
  -  零知识证明的聚合验证：包括加和证明的聚合验证、乘积证明的聚合验证。
- **二进制接口**，包括所有核心密码算法的高性能二进制接口。
- **FFI接口**，支持交叉编译跨语言、跨平台所调用的FFI适配接口。
  
**WeDPR-Lab-Crypto v1.0.0版本**开源主要内容如下：

- **核心密码算法组件**，包括：

  - 基础编解码；

  - 公钥加解密算法，包括基于Secp256k1曲线的ECIES加解密；
  - 哈希算法，包括Keccak256哈希算法与国密SM3；
  - 签名及验证，包括ECDSA签名与国密SM2；
  - 离散对数系统的零知识证明算法，包括加和证明及验证、乘积证明及验证；
  - 零知识范围证明及验证；
  - 基于椭圆曲线的可验证随机函数VRF(Verifiable Random Functions)

- **FFI接口**，支持交叉编译跨语言、跨平台所调用的FFI适配接口。