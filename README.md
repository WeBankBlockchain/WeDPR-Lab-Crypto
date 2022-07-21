# 项目背景

![WeDPR](https://wedpr-lab.readthedocs.io/zh_CN/latest/_static/images/wedpr_logo.png)

WeDPR是一系列**即时可用场景式**隐私保护高效解决方案套件和服务（参见[WeDPR白皮书](https://mp.weixin.qq.com/s?__biz=MzU0MDY4MDMzOA==&mid=2247483910&idx=1&sn=7b647dec9f046f1e6f94d103897f7efb&scene=19#wechat_redirect)），由微众银行区块链团队自主研发。方案致力于解决业务数字化中隐私不“隐”、共享协作不可控等隐私保护风险痛点，消除隐私主体的隐私顾虑和业务创新的合规壁垒，助力基于隐私数据的核心价值互联和新兴商业探索，营造公平、对等、共赢的多方数据协作环境，达成数据价值跨主体融合和数据治理的可控平衡。

WeDPR具备以下特色和优势：

- **场景式解决方案**：已基于具有共性的场景需求，提炼出公开可验证密文账本、多方密文决策、多方密文排名、多方密文计算、多方安全随机数生成、选择性密文披露等高效技术方案框架模板，可应用于支付、供应链金融、跨境金融、投票、选举、榜单、竞拍、招标、摇号、抽检、审计、隐私数据聚合分析、数字化身份、数字化资质凭证、智慧城市、智慧医疗等广泛业务场景。
- **即时可用**：高性能、高易用、跨平台跨语言实现、不依赖中心化可信服务、不依赖可信硬件、支持国密算法标准、隐私效果公开可验证，5分钟一键构建示例应用。
- **透明可控**：隐私控制回归属主，杜绝数据未授权使用，在『数据可用而不可见』的基础上，进一步实现数据使用全程可监管、可追溯、可验证。

WeDPR全面拥抱开放，将陆续开源一系列核心算法组件，进一步提升系统安全性的透明度，提供更透明、更可信的隐私保护效果。WeDPR-Lab就是这一系列开源的**核心算法组件**的集合。

为便于开发者**仅对WeDPR-Lab中的密码算法组件进行选择性使用**，我们将WeDPR-Lab中涉及的所有密码算法组件进行拆分、迁移，重新独立包装形成一个新的密码模块仓库WeDPR-Lab-Crypto。

**WeDPR-Lab-Crypto v1.2.0版本**开源主要内容如下：

- 核心密码算法组件：**n选k不经意传输算法**：

  - 其中，n和k均为任意正整数，k<n。
  
  对于以下场景：
  
  - 数据方的数据目录中共有n条消息记录
  
  - 查询方选择k个消息的索引向数据方查询消息
  
  不经意传输算法能实现的具体隐私效果是：
  
  - 数据方无法得知查询方的查询索引，即：查询方查询索引隐私；
  
  - 除了所查索引的消息外，查询方无法得知数据方数据目录中的其他消息，即：数据方数据隐私。
  
- **二进制接口**，包括所有核心密码算法的高性能二进制接口；


**WeDPR-Lab-Crypto v1.1.0版本**开源主要内容如下：

- **核心密码算法组件**，包括：

  -  分组加密算法：包括AES-256、国密SM4；
  
  -  哈希算法：包括SHA3、BLAKE2、RIPEMD-160；
  
  -  椭圆曲线计算：包括椭圆曲线BN128的点加、点乘及双线性对操作； 
  
  -  数字签名算法：包括Ed25519；
  
  -  零知识证明的聚合验证：包括加和证明的聚合验证、乘积证明的聚合验证。

- **二进制接口**，包括所有核心密码算法的高性能二进制接口；

- **FFI接口**，支持交叉编译跨语言、跨平台所调用的FFI适配接口。
  

**WeDPR-Lab-Crypto v1.0.0版本**开源主要内容如下：

- **核心密码算法组件**，包括：

  - 基础编解码；
 
  - 公钥加解密算法，包括基于Secp256k1曲线的ECIES加解密；
  
  - 哈希算法，包括Keccak256哈希算法与国密SM3；
  
  - 签名及验证，包括ECDSA签名与国密SM2；
  
  - 离散对数系统的零知识证明算法，包括加和证明及验证、乘积证明及验证；
  
  - 零知识范围证明及验证；
  
  - 基于椭圆曲线的可验证随机函数VRF(Verifiable Random Functions)。

- **FFI接口**，支持交叉编译跨语言、跨平台所调用的FFI适配接口。

（说明：由于在进行密码算法组件迁移过程中存在接口变动，所以WeDPR-Lab-Crypto v1.0.0与WeDPR-Lab Core v1.3.0之前版本的密码算法可能存在部分接口不兼容的情况，未来我们会持续进行修复、更新。）

欢迎社区伙伴参与WeDPR-Lab的共建，一起为可信开放数字新生态的构建打造坚实、可靠的技术底座。

# 安装

### 安装Rust环境

安装nightly版本的Rust开发环境，可参考[Rust官方文档](https://www.rust-lang.org/zh-CN/tools/install)。
```bash
rustup default nightly
```

### 下载WeDPR-Lab-Crypto源代码

使用git命令行工具，执行如下命令。

```bash
git clone https://github.com/WeBankBlockchain/WeDPR-Lab-Crypto.git
```

# 条件编译

WeDPR-Lab-Crypto支持灵活的定制化算法选择，用户可根据业务场景、实际需求选择对应的密码算法。

譬如，若用户只希望使用“ECIES加解密算法”的Java调用接口，则只需在WeDPR-Lab Crypto的Java FFI目录下，打开ECIES加解密算法对应的特性进行编译，即进行如下条件编译即可：

```bash
cd ffi/ffi_java/ffi_java_crypto/
cargo build --features "wedpr_f_base64, wedpr_f_ecies_secp256k1" --no-default-features
```


**只有../ffi目录下涉及条件编译。**其中，除**ffi_c/ffi_c_crypto和ffi_java/ffi_java_crypto**，ffi_commom， ffi_macros与ffi_c/ffi_c_commom都为工具类方法，无需编译。

### ffi_c与ffi_java条件编译方法

（以ffi_c目录下的条件编译为例，ffi_java与之类似）

1. 进入ffi_c目录：

```bash
cd ffi/ffi_c/ffi_c_crypto
```

2. 查看当前目录下的Cargo.toml中的[features]，明确本目录所有的条件编译选项。

3. 使用cargo build进行编译时，默认打开了所有条件编译选项（默认编解码方式为base64），编译完成后，即生成本目录下所有密码算法的调用接口。

4. 若只需使用部分密码算法的调用接口，则开启该密码算法对应的条件编译选项，编译时使用：

```bash
cargo build --features "一个或多个feature名" --no-default-features
```

其中，选择"一个或多个feature名"时，注意(binary接口无须使用base64或hex编码)：

|    注意事项    |                         条件编译选项                         |
| :------------: | :----------------------------------------------------------: |
| 互斥条件编译项 |                 wedpr_f_base64, wedpr_f_hex                  |
| 必选条件编译项 |                 wedpr_f_base64或wedpr_f_hex                  |
| 可选条件编译项 | "wedpr_f_ecies_secp256k1", "wedpr_f_signature_secp256k1", "wedpr_f_hash_keccak256", "wedpr_f_signature_sm2", "wedpr_f_hash_sm3", "wedpr_f_vrf_curve25519", "wedpr_f_crypto_block_cipher_aes", "wedpr_f_crypto_block_cipher_sm4", "wedpr_f_hash_ripemd160", "wedpr_f_hash_sha3", "wedpr_f_hash_blake2b", "wedpr_f_signature_ed25519"  |

# 接口文档

查看WeDPR所有crate对应文档

- [点击这里](https://crates.io/search?q=wedpr)

# 其他相关文档

- [WeDPR方案白皮书](https://mp.weixin.qq.com/s?__biz=MzU0MDY4MDMzOA==&mid=2247483910&idx=1&sn=7b647dec9f046f1e6f94d103897f7efb&scene=19#wechat_redirect)
- [WeDPR-Lab用户文档](https://wedpr-lab.readthedocs.io/zh_CN/latest/index.html)

# 项目贡献

- 点亮我们的小星星(点击项目右上方Star按钮)
- 提交代码(Pull Request)，参考我们的代码[贡献流程](./CONTRIBUTING.md)
- [提问和提交BUG](https://github.com/WeBankBlockchain/WeDPR-Lab-Crypto/issues)
