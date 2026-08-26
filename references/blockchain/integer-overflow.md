# 整数溢出 (Integer Overflow)

## 原理

Solidity 0.8.0 之前没有内置整数溢出检查，攻击者可通过溢出绕过余额检查、转移超额代币等。

## 经典漏洞

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract Vulnerable {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) public {
        // 漏洞：未检查溢出
        balances[msg.sender] -= amount;  // 下溢
        balances[to] += amount;          // 上溢
    }
    
    function batchTransfer(address[] memory recipients, uint256 amount) public {
        // 漏洞：amount * recipients.length 可能溢出
        uint256 total = amount * recipients.length;
        require(balances[msg.sender] >= total);
        
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;
        }
        balances[msg.sender] -= total;
    }
}
```

## 攻击示例

### 1. 下溢攻击

```solidity
// 初始余额：0
// 转账 1
// 0 - 1 = 2^256 - 1（下溢）
// 攻击者获得巨额余额

balances[attacker] = 0;
balances[attacker] -= 1;  // 变为 2^256 - 1
```

### 2. 上溢攻击

```solidity
// 初始余额：2^256 - 1
// 增加 1
// 2^256 - 1 + 1 = 0（上溢）

balances[victim] = type(uint256).max;
balances[victim] += 1;  // 变为 0
```

### 3. BEC 代币攻击

```solidity
// BEC 代币的 batchTransfer 函数
// amount * recipients.length 溢出
// 攻击者转出巨额代币

// 攻击参数
// recipients.length = 2
// amount = 2^255
// total = 2^255 * 2 = 2^256 = 0（溢出）
// require(balances[msg.sender] >= 0) 通过
// 攻击者转出 2^255 给每个地址
```

## 防护方法

### 1. SafeMath

```solidity
// Solidity 0.7 及以下
import "@openzeppelin/contracts/math/SafeMath.sol";

using SafeMath for uint256;

function transfer(address to, uint256 amount) public {
    balances[msg.sender] = balances[msg.sender].sub(amount);
    balances[to] = balances[to].add(amount);
}
```

### 2. Solidity 0.8.0+ 内置检查

```solidity
// Solidity 0.8.0+ 自动检查溢出
pragma solidity ^0.8.0;

function transfer(address to, uint256 amount) public {
    balances[msg.sender] -= amount;  // 自动检查
    balances[to] += amount;          // 自动检查
}
```

### 3. unchecked 块

```solidity
// Solidity 0.8.0+ 可使用 unchecked 关闭检查
pragma solidity ^0.8.0;

function transfer(address to, uint256 amount) public {
    unchecked {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```

## 攻击变种

### 1. 时间戳溢出

```solidity
// 时间戳溢出
// uint256 timestamp = block.timestamp + 100;
// 如果 block.timestamp 接近 2^256，会溢出
```

### 2. 数组长度溢出

```solidity
// 数组长度溢出
// uint256[] memory arr = new uint256[](2^256 - 1);
// 会导致内存问题
```

### 3. 循环溢出

```solidity
// 循环变量溢出
// for (uint8 i = 0; i < 256; i++) {
//     // i 会溢出，导致无限循环
// }
```

### 4. 类型转换溢出

```solidity
// uint256 转 uint8
// uint256 a = 256;
// uint8 b = uint8(a);  // b = 0
```

### 5. 除法精度

```solidity
// 整数除法精度问题
// uint256 a = 5;
// uint256 b = 3;
// uint256 c = a / b;  // c = 1，不是 1.666...
```

## 2024-2026 新技术点

### 1. Solidity 0.8.0+ 绕过

```solidity
// 使用 unchecked 块
// 类型转换
// 位运算
```

### 2. Vyper 整数溢出

```solidity
// Vyper 的整数处理
// 可能存在不同的问题
```

### 3. Yul 汇编溢出

```solidity
// 内联汇编不检查溢出
// assembly {
//     let result := add(a, b)  // 不检查
// }
```

### 4. 跨合约溢出

```solidity
// 合约 A 调用合约 B
// B 的返回值在 A 中溢出
```

### 5. 闪电贷溢出

```solidity
// 闪电贷放大溢出效果
```

### 6. MEV 溢出

```solidity
// MEV 机器人利用溢出
```

### 7. Layer 2 溢出

```solidity
// Layer 2 的特定溢出
```

### 8. 账户抽象溢出

```solidity
// ERC-4337 的溢出
```

### 9. 零知识证明溢出

```solidity
// zk-SNARK 验证中的溢出
```

### 10. AI 辅助检测

```python
# ML 辅助
# 自动检测溢出
# 模式识别
```

## 工具推荐

- **Slither** — 静态分析
- **Mythril** — 符号执行
- **Echidna** — 模糊测试
- **manticore** — 符号执行

## 参考链接

- [SWC-101: Integer Overflow](https://swcregistry.io/docs/SWC-101)
- [BEC Token Hack](https://www.peckshield.com/2018/04/25/bec/)
- [SafeMath](https://docs.openzeppelin.com/contracts/3.x/api/utils#SafeMath)
