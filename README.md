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

# 安全修复与升级兼容性

当前修改包含以下协议及格式升级，调用方应同步升级，不能混用新旧实现：

- 离散对数 ZKP 的五种批验证使用完整标量域中的非零随机系数；空批次和任一列表长度不一致都会被拒绝。证明编码保持不变。
- AES/SM4 crate 升至 **2.0.0**。`encrypt`/`decrypt` 的参数形式不变，输出改为认证密文：`WDPRETM\x01`（8 字节）+ PKCS#7 CBC 密文 + HMAC-SHA256（32 字节）。HKDF-SHA256 按算法域派生独立的加密和认证密钥；MAC 覆盖算法域、IV、版本头和 CBC 密文，验证通过后才解密。每次加密必须生成新的不可预测的 16 字节 IV。SM4 的此组合使用 SHA256/HMAC，不应据此声称整套组合符合国密认证要求。
- 二进制 C 接口的加密输出空间须为 `16 * (明文长度 / 16 + 1) + 40` 字节。空间不足时返回 `-1`，将所需空间写入 `output->len`，不写输出数据。Rust 可调用对应 cipher 类型的 `ciphertext_len` 检查长度与整数溢出。文本 C/JNI 接口同样返回新版认证密文。
- **旧的裸 CBC 密文不会回退解密。** 已有数据应在可信、隔离的旧版本迁移工具中解密，经业务来源校验后，以新密钥和新 IV 重新加密；旧数据没有认证信息，不能凭补加标签追溯确认其真实性。新旧版本必须使用独立密钥，生产解密入口不得保留自动回退。
- KV OT crate 升至 **0.3.0**，查询及响应的 `version` 必须为 `2`。每个选择通过 `choices` 传送独立的 `(point_x, point_y, point_z)`；响应使用 `encrypted_choices`，每项含 `key_basepoint`、16 字节 `iv` 和认证密文，已移除 `fingerprint`。调用顺序仍为 `receiver_init`、`sender_init`、`receiver_decrypt`。查询方需保留完整私有状态，不能复用旧的共享掩码状态；收发双方及自行实现的序列化代码必须一起升级。
- KV OT 拒绝重复的数据库 ID、空查询、单位元查询、长度不一致和旧版本；选择 ID 应唯一，所选 ID 必须存在。认证标签用于本地确认解密结果，所选消息缺失或被篡改时整次解密报错。不要向数据方反馈具体哪个选择解密失败。

KV OT 的安全模型仍是半诚实参与方，公开选择数量和填充后的消息长度；这些修复不构成对恶意参与方安全性的证明。服务端仍需限制每次查询的选择数量，并实施业务授权。

二选一消息 OT 随 crate **0.4.0** 一并迁移至版本 2 KV OT 的单选择实现，使用固定且不同的两条 ID。旧版直接以压缩曲线点 XOR 明文，会泄露编码固定位置对应的明文位，也无法检测篡改；该路径已移除。`receiver_decrypt` 现返回 `Result<Vec<u8>, WedprError>`，私有状态保留查询上下文且不再公开或实现 `Debug`。公开查询及两条响应采用 KV OT v2 的带版本结构；调用方必须更新序列化与错误处理，不接受旧 XOR 响应。半诚实模型及失败不反馈的要求同样适用。

**旧 secp256k1 VRF 已关闭（crate 2.0.0）。** nonce 修复无法解决 `H=G*hash(PK || message)` 使 Gamma 及输出可由公钥公开计算的问题。`prove`、`prove_fast`、`decode_proof`、`proof_to_hash` 均报错，`verify` 返回 false，`encode_proof` 返回无效的空数据；原生证明接口返回失败且不写输出。密钥派生与规范压缩公钥校验仍可用。生产调用方必须把失败作为不可用状态传播，禁止回退旧版本或把空证明作为随机数。该分支没有启用任何实验替代协议。

如果在 nonce 修复前，同一旧私钥生成过两份不同挑战且外部可获取的证明，应按私钥泄露处置并轮换；同一密钥用于其他协议时也需撤销对应权限。nonce 修复后的旧协议输出仍可预测，不能用于安全随机选择。替代协议及部署须单独审查，并协调所有验证节点与历史数据处理。

# 安装

## 原生接口与签名校验加固

本轮补丁基于官方 `fisco/main` 的 `3beca5a`，保留已有的 ZKP 批验证、OT 与认证加密修复。

- `wedpr_ffi_common` 升至 **2.0.0**：Rust 读缓冲区辅助函数返回借用切片与 `Result`，不再用 `Vec::from_raw_parts` 接管 C 内存；写入前检查容量和空指针，失败不写数据。C ABI 与缓冲区结构布局不变，二进制入口会传播失败状态。使用这些 Rust 辅助函数的外部项目需要更新调用方式。非空原生指针仍须由调用方保证其实际内存范围有效。
- C 字符串接口拒绝空指针；JNI 在结果类缺失、字段不匹配或分配失败时保留 Java 异常并返回空对象，避免 Rust panic 跨越 JNI。已包含真实 JVM 的缺失类、缺失字段、正常加解密及篡改拒绝回归脚本。
- C 缓冲区描述符先以原生指针检查空值与对齐，再转换为 Rust 类型；JNI 错误对象及 C 诊断日志不再回显私钥、明文等输入。宏依赖统一使用本仓库修复后的版本，避免链接回旧错误处理实现。
- `wedpr_ffi_macros` **1.2.0** 的 ByteBuffer 转换宏复制到 Java 字节数组并返回 Java 持有的堆缓冲区，避免引用已经失效的 Rust 临时内存；不再返回 direct buffer。现有生产入口没有使用该宏，外部使用方不能依赖 `isDirect()` 为 true。
- Base64/Hex coder **1.2.0** 的解码失败不再输出原始输入，FFI common 固定使用本仓库修复后的 coder，避免异常格式的私钥或明文被底层依赖写入日志。回归测试会捕获子进程的 stdout/stderr 检查合成敏感标记是否泄露。
- Ed25519 使用严格验签，拒绝小阶公钥、单位元签名及非规范标量。SM2 要求私钥在 `[1, n-2]`，拒绝零、`n-1` 及越界私钥；`sign_fast` 还会核对公私钥匹配。
- ZKP 标量解码要求规范编码，五种固定格式证明要求精确长度，拒绝截断及追加字节。正常生成的证明格式保持不变。
- Ed25519 crate 升至 **1.2.0**，内部采用 `ed25519-dalek 2.2` / `curve25519-dalek 4.1.3`；32 字节私钥种子、公钥和 64 字节签名格式保持不变，继续使用严格验签。secp256k1 签名 crate 升至 **1.2.0**，验签及公钥恢复均拒绝高 S 等价变形，不自动规范化攻击者提交的签名。
- Curve25519 VRF crate 升至 **1.2.0**，拒绝单位元公钥和 Gamma、非规范标量，`prove_fast` 必须提供匹配的公钥。正常密钥对应的输出保持不变；`proof_to_hash` 的结构检查不能替代 `verify(public_key, message)`，使用输出前必须验证证明。
- FISCO Java SDK 的独立字符串 VRF 实现（third-party crate **0.2.0**）同样拒绝单位元及非规范标量，证明要求精确的 `hex[64]|hex[64]|hex[64]` 格式（每段为 64 个小写十六进制字符），并在分配前限制总长度为 194 字节。正常输出保持不变；大写 hex 等历史宽松编码会被拒绝。
- 仍依赖 dalek v1 的 ZKP、OT 与 Curve25519 VRF，通过根 `Cargo.toml` 的 `[patch.crates-io]` 使用 `third_party/curve25519-dalek-legacy`，回移 RUSTSEC-2024-0344 的标量减法优化屏障，保持原有编码。来源、校验值和两处源码差异见该目录 `PATCHES.txt`。**Cargo 的 patch 不会被下游工作区自动继承**：集成方必须在自己的工作区根保留同样的映射并指向这份补丁源码；仅更新版本号或发布仍指向上游 v1 的依赖不能获得此修复。该回移不代表完成全面侧信道审计。

这些改动收紧了历史上会接受的无效输入。用于链上或其他共识验证时，应协调验证规则的激活及历史数据兼容策略，不能仅在部分节点替换动态库。

本轮审查仍有明确边界：SM2 的 `wedpr_l_libsm` 后端使用可变时间的大整数运算，私钥范围检查没有解决其侧信道风险；需要独立评估并以互操作测试支持后端迁移。BN128 的 `bn-plus 0.4.4` 依赖在本轮工具链上存在旧序列化 trait 构建错误，相关模块没有通过全量构建及运行验证，不能从安全回归任务通过推断整个工作区已通过。新增 CI 的 Linux 运行结果也需要以实际远端状态为准。上述修复与功能测试不构成完整密码学安全证明。

JNI 回归测试示例（先构建相应平台的二进制 JNI 库）：

```bash
python3 ffi/ffi_java/ffi_java_crypto_binary/tests/check_jni_failures.py \
  --library target/debug/libffi_java_crypto_binary.so --java-home "$JAVA_HOME"
```

### 安装Rust环境

本仓库固定使用 `nightly-2025-04-11`（Rust 1.88 nightly），以满足新版 Ed25519 至少 Rust 1.81 的要求，同时兼容旧范围证明依赖的 feature 声明；原 `nightly-2024-02-25` 不再满足要求。安全回归还在 Rust 1.94.1 上测试，旧范围证明在 stable 下需要仅对 `wedpr_l_bulletproofs` 设置 `RUSTC_BOOTSTRAP`；这不能解决独立的旧 BN128 依赖构建问题。可参考[Rust官方文档](https://www.rust-lang.org/zh-CN/tools/install)。
```bash
rustup toolchain install nightly-2025-04-11
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
