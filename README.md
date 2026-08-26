# CTF 解题全能助手 (Skill)

分层 CTF 知识库，覆盖主流 CTF 比赛的七大方向。按需查阅，不一次性加载。

## 覆盖方向

| 方向 | 文件数 | 核心能力 |
|------|--------|----------|
| **Web** | 17 | SQL注入/XSS/SSTI/SSRF/XXE/反序列化/命令注入/原型链污染/JWT/请求走私/GraphQL/竞态/逻辑漏洞 |
| **Pwn** | 12 | 栈溢出/格式化字符串/堆基础/UAF/tcache/fastbin/unsorted bin/House of系列/IO_FILE/内核利用 |
| **Crypto** | 9 | RSA攻击全集/AES(EBC/CBC/CTR/GCM)/ECC/哈希/格攻击/LLL/Coppersmith/Padding Oracle/LCG |
| **Reverse** | 8 | 静态分析/动态分析/反调试/算法识别/OLLVM反混淆/Android逆向/WASM逆向 |
| **Misc** | 6 | 数字取证/隐写术/流量分析/OSINT/编码解码 |
| **Blockchain** | 5 | 重入攻击/整数溢出/访问控制/DeFi攻击(闪电贷/MEV/价格操纵) |
| **Cloud** | 4 | 容器逃逸/Kubernetes攻击/AWS+Azure+GCP metadata攻击 |

## 使用方式

### 安装到 AI Agent Skill 目录

```bash
# 直接拷贝到你的 skill 目录 (路径按实际环境调整)
cp -r ctf/ <your-skill-dir>/ctf/
```

### 自动触发

安装后，当用户涉及 CTF 比赛、漏洞利用、payload 构造、绕过防护等场景时，AI agent 会自动加载此 skill。

### 工作流

```
SKILL.md (路由) → 方向 README.md (子路由) → 具体漏洞文件 → 攻击链 + payload
```

## 文件结构

```
ctf/
├── SKILL.md                      ← 路由入口 (AI 读此文件启动)
├── references/
│   ├── web/                      ← Web 渗透 (17 文件)
│   │   ├── README.md
│   │   ├── sqli.md              ← SQL 注入
│   │   ├── xss.md               ← XSS
│   │   ├── ssti.md              ← 模板注入
│   │   ├── ssrf.md              ← SSRF
│   │   ├── xxe.md               ← XXE
│   │   ├── csrf.md              ← CSRF
│   │   ├── file-upload.md       ← 文件上传
│   │   ├── file-inclusion.md    ← 文件包含
│   │   ├── deserialization.md   ← 反序列化
│   │   ├── command-injection.md ← 命令注入
│   │   ├── prototype-pollution.md ← 原型链污染
│   │   ├── jwt-attacks.md       ← JWT 攻击
│   │   ├── request-smuggling.md ← HTTP 请求走私
│   │   ├── graphql-attacks.md   ← GraphQL 攻击
│   │   ├── race-conditions.md   ← 竞态条件
│   │   └── logic-vulnerabilities.md ← 逻辑漏洞
│   ├── pwn/                      ← 二进制利用 (12 文件)
│   │   ├── README.md
│   │   ├── stack-overflow.md
│   │   ├── format-string.md
│   │   ├── heap-basics.md
│   │   ├── uaf.md
│   │   ├── tcache-attacks.md
│   │   ├── fastbin-attacks.md
│   │   ├── unsorted-bin-attacks.md
│   │   ├── house-of-series.md
│   │   ├── io-file-attacks.md
│   │   ├── modern-protections.md
│   │   └── kernel-pwn.md
│   ├── reverse/                  ← 逆向工程 (8 文件)
│   ├── crypto/                   ← 密码学 (9 文件)
│   ├── misc/                     ← 杂项 (6 文件)
│   ├── blockchain/               ← 区块链 (5 文件)
│   └── cloud/                    ← 云安全 (4 文件)
└── scripts/                      ← 辅助脚本
    ├── generate_payloads.py      ← Payload 生成器
    ├── encoding_toolkit.py       ← 编码解码工具箱
    └── crypto_helper.py          ← 密码学攻击辅助
```

## 每个漏洞文件包含

- 原理说明
- 攻击链 (步骤式)
- Payload 模板 (可直接使用)
- 绕过技巧 (WAF/过滤/防护)
- 2024-2026 新技术点 (最新 CVE/bypass/利用链)
- 工具推荐 + 参考链接

## 脚本用法

```bash
# Payload 生成
python scripts/generate_payloads.py

# 编码解码
python scripts/encoding_toolkit.py

# 密码学攻击 (RSA/AES/ECC/LCG 等)
python scripts/crypto_helper.py
```

## 设计原则

- **分层读取**: SKILL.md → 方向 README → 具体文件，节省 token
- **自包含**: 每个文件独立，可单独使用
- **实战导向**: payload 模板可直接替换变量使用
- **版本敏感**: glibc 版本/PHP 版本/OpenSSL 版本标注

## 许可

仅供 CTF 比赛和授权渗透测试使用。
