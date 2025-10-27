# 实现文档 / Implementation Documentation

## 项目概述 / Project Overview

本项目是一个教育性的密码学算法实现，展示了 Diffie-Hellman 密钥交换和 RSA 加密算法的工作原理，以及针对这些算法的常见攻击和防御措施。

This project is an educational cryptographic implementation demonstrating how Diffie-Hellman key exchange and RSA encryption work, along with common attacks and defenses against these algorithms.

## 文件说明 / File Descriptions

### 核心实现 / Core Implementations

#### `src/diffie_hellman.py`
Diffie-Hellman 密钥交换的面向对象实现。

Key features:
- 使用 2048 位安全素数（RFC 3526）
- 高效的模幂运算
- 公钥验证以防止小子群攻击
- 密钥派生函数 (SHA-256 based KDF)

Main class: `DiffieHellman`
- `generate_private_key()`: 生成私钥
- `generate_public_key()`: 生成公钥
- `compute_shared_secret(other_public_key)`: 计算共享密钥
- `derive_key()`: 从共享密钥派生加密密钥
- `_validate_public_key(public_key)`: 验证接收到的公钥

#### `src/rsa.py`
RSA 加密算法的面向对象实现。

Key features:
- 可配置密钥大小（默认 2048 位）
- Miller-Rabin 素性测试
- OAEP-like 填充方案
- 数字签名和验证功能

Main class: `RSA`
- `generate_keys()`: 生成密钥对
- `encrypt(plaintext, public_key)`: 加密消息
- `decrypt(ciphertext, private_key)`: 解密消息
- `sign(message)`: 对消息签名
- `verify(message, signature, public_key)`: 验证签名

### 攻击和防御演示 / Attacks and Defenses

#### `src/dh_attacks.py`
Diffie-Hellman 攻击和防御的演示。

包含的攻击 / Included attacks:
1. **中间人攻击 (MITM)**: `DHAttacks.man_in_the_middle_attack()`
   - 演示攻击者如何拦截密钥交换
   - 展示为什么需要认证

2. **小子群攻击**: `DHAttacks.small_subgroup_attack()`
   - 演示使用小子群元素的攻击
   - 展示公钥验证的重要性

包含的防御 / Included defenses:
1. **认证密钥交换**: `DHDefenses.authenticated_key_exchange()`
   - 使用 RSA 签名进行认证
   - 防止中间人攻击

2. **安全参数选择**: `DHDefenses.secure_parameter_selection()`
   - 使用大素数
   - 正确的参数验证

#### `src/rsa_attacks.py`
RSA 攻击和防御的演示。

包含的攻击 / Included attacks:
1. **小指数攻击**: `RSAAttacks.small_exponent_attack()`
   - 当 m^e < n 时的攻击
   - 展示填充的重要性

2. **因式分解攻击**: `RSAAttacks.factorization_attack()`
   - 对小素数的分解
   - 展示大素数的必要性

3. **共模攻击**: `RSAAttacks.common_modulus_attack()`
   - 两个用户共享同一模数的风险
   - 使用扩展欧几里得算法恢复明文

4. **时序攻击概念**: `RSAAttacks.timing_attack_concept()`
   - 解释时序攻击原理
   - 讨论防御措施（盲化、恒定时间实现）

包含的防御 / Included defenses:
1. **正确的填充方案**: `RSADefenses.proper_padding_scheme()`
   - OAEP-like 填充
   - 非确定性加密

2. **安全的密钥生成**: `RSADefenses.secure_key_generation()`
   - 大密钥尺寸
   - 强随机素数生成
   - 素数间距检查

3. **数字签名认证**: `RSADefenses.digital_signatures_for_authentication()`
   - 消息认证
   - 完整性保护

### 演示脚本 / Demonstration Scripts

#### `main.py`
交互式主程序，提供菜单选择运行不同的演示。

Features:
- 基本 D-H 密钥交换演示
- RSA 加密/解密演示
- RSA 数字签名演示
- 完整的攻击和防御演示

#### `test_crypto.py`
自动化测试脚本，验证所有功能。

Test coverage:
- Diffie-Hellman 功能测试
- RSA 功能测试
- 集成测试（认证密钥交换）

## 使用示例 / Usage Examples

### 基本 Diffie-Hellman 使用 / Basic Diffie-Hellman Usage

```python
from src.diffie_hellman import DiffieHellman

# Alice
alice = DiffieHellman()
alice.generate_private_key()
alice_public = alice.generate_public_key()

# Bob
bob = DiffieHellman()
bob.prime, bob.generator = alice.get_parameters()
bob.generate_private_key()
bob_public = bob.generate_public_key()

# 交换公钥并计算共享密钥
alice_shared = alice.compute_shared_secret(bob_public)
bob_shared = bob.compute_shared_secret(alice_public)

# alice_shared == bob_shared
key = alice.derive_key()  # 用于对称加密
```

### 基本 RSA 使用 / Basic RSA Usage

```python
from src.rsa import RSA

# 生成密钥
rsa = RSA(key_size=2048)
public_key, private_key = rsa.generate_keys()

# 加密
message = "Secret message"
ciphertext = rsa.encrypt(message, public_key)

# 解密
plaintext = rsa.decrypt(ciphertext, private_key)

# 签名
signature = rsa.sign(message)
is_valid = rsa.verify(message, signature, public_key)
```

### 运行演示 / Running Demonstrations

```bash
# 交互式菜单
python main.py

# 运行特定演示
python src/dh_attacks.py
python src/rsa_attacks.py

# 运行测试
python test_crypto.py
```

## 安全考虑 / Security Considerations

⚠️ **重要警告 / Important Warning:**

本实现仅用于教育目的！不要在生产环境中使用！

This implementation is for educational purposes only! DO NOT use in production!

### 已知限制 / Known Limitations

1. **随机数生成**: 使用 Python 的 `random` 模块，不够安全
   - 生产环境应使用 `secrets` 或 `os.urandom`

2. **素数生成**: Miller-Rabin 测试的轮数较少
   - 生产环境需要更多轮数或使用专业库

3. **填充方案**: 简化版 OAEP，不完全符合标准
   - 生产环境应使用标准 OAEP (PKCS#1 v2.0)

4. **时序攻击**: 未实现恒定时间算法
   - 容易受到时序攻击

5. **侧信道攻击**: 未考虑功耗分析、缓存时序等
   - 生产环境需要考虑硬件安全

### 推荐的生产库 / Recommended Production Libraries

- **Python**: 
  - `cryptography` (推荐)
  - `PyCryptodome`
  
- **其他语言**:
  - OpenSSL
  - Bouncy Castle (Java)
  - libsodium

## 学习路径 / Learning Path

1. **理解基础概念**:
   - 运行基本演示 (main.py 选项 1-3)
   - 理解密钥交换和加密的区别

2. **学习攻击**:
   - 运行攻击演示 (main.py 选项 4-5)
   - 理解每种攻击的原理和条件

3. **理解防御**:
   - 研究防御机制的实现
   - 理解为什么这些措施有效

4. **深入代码**:
   - 阅读源代码和注释
   - 尝试修改参数观察效果

5. **扩展学习**:
   - 研究其他密码学算法
   - 学习密码学分析技术
   - 了解现代密码学标准

## 参考资源 / References

### 书籍 / Books
- "Applied Cryptography" by Bruce Schneier
- "Introduction to Modern Cryptography" by Katz & Lindell
- "Cryptography Engineering" by Ferguson, Schneier, and Kohno

### 在线资源 / Online Resources
- RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups
- PKCS #1: RSA Cryptography Specifications
- NIST Special Publications on Cryptography

### 工具和库 / Tools and Libraries
- Sage (mathematical software)
- OpenSSL documentation
- Python cryptography library documentation

## 贡献 / Contributing

欢迎提出改进建议和问题报告！

Issues and improvement suggestions are welcome!

## 许可 / License

本项目仅供教育和学习使用。

This project is for educational and learning purposes only.
