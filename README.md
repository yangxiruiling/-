# Cryptographic Algorithms: D-H and RSA Implementation

面向对象实现 Diffie-Hellman (D-H) 和 RSA 算法，以及针对它们的攻击与防御

Object-oriented implementation of Diffie-Hellman and RSA algorithms with demonstrations of attacks and defense mechanisms.

## 项目简介 / Project Overview

本项目实现了两个核心的密码学算法：
- **Diffie-Hellman (D-H) 密钥交换**: 允许两方在不安全信道上建立共享密钥
- **RSA 加密算法**: 非对称加密系统，用于安全通信和数字签名

This project implements two core cryptographic algorithms:
- **Diffie-Hellman (D-H) Key Exchange**: Allows two parties to establish a shared secret over an insecure channel
- **RSA Encryption**: Asymmetric encryption system for secure communication and digital signatures

## 特性 / Features

### 核心实现 / Core Implementations
- ✅ 面向对象的 Diffie-Hellman 密钥交换实现
- ✅ 面向对象的 RSA 加密/解密实现
- ✅ RSA 数字签名功能
- ✅ 安全参数生成和验证

### 安全分析 / Security Analysis
- ✅ **D-H 攻击演示**:
  - 中间人攻击 (Man-in-the-Middle Attack)
  - 小子群攻击 (Small Subgroup Attack)
- ✅ **RSA 攻击演示**:
  - 小指数攻击 (Small Exponent Attack)
  - 因式分解攻击 (Factorization Attack)
  - 共模攻击 (Common Modulus Attack)
  - 时序攻击概念 (Timing Attack Concepts)

### 防御机制 / Defense Mechanisms
- ✅ **D-H 防御**:
  - 认证密钥交换 (Authenticated Key Exchange)
  - 安全参数选择 (Secure Parameter Selection)
  - 公钥验证 (Public Key Validation)
- ✅ **RSA 防御**:
  - 正确的填充方案 (Proper Padding - OAEP-like)
  - 安全的密钥生成 (Secure Key Generation)
  - 数字签名认证 (Digital Signatures for Authentication)

## 项目结构 / Project Structure

```
.
├── main.py                      # 主演示程序 / Main demonstration script
├── src/
│   ├── diffie_hellman.py       # D-H 算法实现 / D-H implementation
│   ├── rsa.py                  # RSA 算法实现 / RSA implementation
│   ├── dh_attacks.py           # D-H 攻击和防御 / D-H attacks & defenses
│   └── rsa_attacks.py          # RSA 攻击和防御 / RSA attacks & defenses
└── README.md                    # 本文件 / This file
```

## 安装和使用 / Installation and Usage

### 环境要求 / Requirements
- Python 3.6 或更高版本 / Python 3.6 or higher
- 无需外部依赖库 / No external dependencies required

### 运行演示 / Running Demonstrations

#### 交互式菜单 / Interactive Menu
```bash
python main.py
```

这将启动交互式菜单，您可以选择运行不同的演示：
1. Diffie-Hellman 密钥交换
2. RSA 加密/解密
3. RSA 数字签名
4. D-H 攻击和防御
5. RSA 攻击和防御
6. 运行所有演示

#### 直接运行特定演示 / Run Specific Demonstrations
```bash
# D-H 攻击和防御演示
python src/dh_attacks.py

# RSA 攻击和防御演示
python src/rsa_attacks.py
```

## 技术细节 / Technical Details

### Diffie-Hellman 实现 / D-H Implementation

**核心功能 / Core Features:**
- 使用 2048 位安全素数 (RFC 3526)
- 模幂运算优化
- 公钥验证防止小子群攻击
- 密钥派生函数 (KDF)

**类方法 / Class Methods:**
```python
dh = DiffieHellman(key_size=2048)
dh.generate_private_key()
dh.generate_public_key()
shared_secret = dh.compute_shared_secret(other_public_key)
encryption_key = dh.derive_key()
```

### RSA 实现 / RSA Implementation

**核心功能 / Core Features:**
- 可配置密钥大小 (默认 2048 位)
- Miller-Rabin 素性测试
- OAEP-like 填充方案
- 数字签名和验证

**类方法 / Class Methods:**
```python
rsa = RSA(key_size=2048)
public_key, private_key = rsa.generate_keys()
ciphertext = rsa.encrypt(message, public_key)
plaintext = rsa.decrypt(ciphertext, private_key)
signature = rsa.sign(message)
is_valid = rsa.verify(message, signature, public_key)
```

## 安全考虑 / Security Considerations

⚠️ **重要提示 / Important Notes:**

本项目仅用于教育目的，演示密码学算法的基本原理。
**不应在生产环境中使用！**

This project is for educational purposes only to demonstrate cryptographic principles.
**DO NOT use in production environments!**

对于生产系统，请使用经过充分测试的密码学库：
- Python: `cryptography`, `PyCryptodome`
- OpenSSL
- 等等

For production systems, use well-tested cryptographic libraries:
- Python: `cryptography`, `PyCryptodome`
- OpenSSL
- etc.

## 学习要点 / Learning Points

### Diffie-Hellman
1. **工作原理**: 如何在不安全信道上建立共享密钥
2. **中间人攻击**: 为什么需要认证
3. **参数选择**: 安全参数的重要性

### RSA
1. **公钥加密**: 非对称加密的基本原理
2. **数字签名**: 如何证明消息真实性
3. **填充方案**: 为什么需要随机化
4. **密钥大小**: 安全性和性能的权衡

### 通用安全原则
1. **不要重复造轮子**: 使用经过验证的密码学库
2. **正确的参数**: 密钥大小、素数选择等
3. **认证很重要**: 防止中间人攻击
4. **随机性**: 密码学安全的随机数生成器

## 贡献 / Contributing

欢迎提交问题和改进建议！

Feel free to submit issues and enhancement requests!

## 许可证 / License

本项目仅供学习和教育目的使用。

This project is for educational and learning purposes only.

## 参考资料 / References

- RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups
- PKCS #1: RSA Cryptography Specifications
- Applied Cryptography by Bruce Schneier
- Cryptography Engineering by Ferguson, Schneier, and Kohno