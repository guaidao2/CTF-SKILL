# DeFi 攻击

## 原理

DeFi（去中心化金融）协议因价格预言机操纵、闪电贷攻击、MEV 等问题被攻击，导致资金损失。

## 常见攻击类型

### 1. 闪电贷攻击

```solidity
// 闪电贷：无需抵押的借贷，需在同一交易内还款
// 攻击者利用闪电贷操纵价格

// 攻击流程
// 1. 闪电贷借入大量代币
// 2. 操纵价格（如 DEX 价格）
// 3. 利用操纵的价格获利
// 4. 还款，保留利润

contract FlashLoanAttack {
    function attack() external {
        // 1. 闪电贷借入 10000 ETH
        aave.flashLoan(address(this), ETH, 10000 ether, "");
        
        // 2. 在 DEX 上卖出，压低价格
        dex.swap(ETH, USDC, 5000 ether);
        
        // 3. 利用低价格从目标协议获利
        target.borrow(1000000 USDC);  // 基于操纵的价格
        
        // 4. 在 DEX 上买回 ETH
        dex.swap(USDC, ETH, 1000000 USDC);
        
        // 5. 还款
        aave.transfer(ETH, 10000 ether);
    }
}
```

### 2. 价格预言机操纵

```solidity
// 漏洞：使用 DEX 价格作为预言机
contract Vulnerable {
    function getPrice() public view returns (uint) {
        // 漏洞：使用单一 DEX 的瞬时价格
        (uint r0, uint r1, ) = pair.getReserves();
        return r1 * 1e18 / r0;
    }
    
    function borrow(uint amount) public {
        uint price = getPrice();
        require(collateral * price >= amount, "Insufficient collateral");
        // ...
    }
}

// 攻击者通过大额交易操纵价格
```

### 3. MEV 攻击

```solidity
// MEV (Maximal Extractable Value)
// 1. 三明治攻击
// 2. 套利
// 3. 清算

// 三明治攻击
// 1. 监控 mempool
// 2. 发现大额交易
// 3. 前置交易（推高价格）
// 4. 受害者交易（更高价格）
// 5. 后置交易（卖出获利）
```

### 4. 清算攻击

```solidity
// 攻击者故意让仓位被清算
// 通过操纵价格触发清算
// 获得清算奖励
```

### 5. 治理攻击

```solidity
// 1. 闪电贷借入治理代币
// 2. 投票通过恶意提案
// 3. 转移资金
// 4. 还款
```

## 经典案例

### 1. bZx 攻击（2020）

```solidity
// 攻击流程
// 1. 闪电贷借入 10000 ETH
// 2. 在 bZx 上抵押 ETH 借入 sUSD
// 3. 在 Kyber/Uniswap 上将 sUSD 换为 ETH
// 4. 价格操纵获利
// 5. 还款
```

### 2. Harvest Finance 攻击（2020）

```solidity
// 攻击流程
// 1. 闪电贷借入 USDC
// 2. 操纵 Curve 池价格
// 3. 在 Harvest 中存入/取出获利
// 4. 还款
```

### 3. Cream Finance 攻击（2021）

```solidity
// 攻击流程
// 1. 闪电贷借入 ETH
// 2. 操纵 yUSD 价格
// 3. 在 Cream 中借入更多资金
// 4. 还款
```

### 4. Beanstalk 攻击（2022）

```solidity
// 攻击流程
// 1. 闪电贷借入 AAVE、DOLA、LUSD、USDC、USDT
// 2. 换取 BEAN 和 3CRV
// 3. 投票通过恶意提案
// 4. 转移资金
// 5. 还款
```

### 5. Euler Finance 攻击（2023）

```solidity
// 攻击流程
// 1. 闪电贷借入 3000 万 DAI
// 2. 利用 donateToReserves 漏洞
// 3. 触发清算
// 4. 获得抵押物
// 5. 还款
```

## 防护方法

### 1. 使用时间加权平均价格（TWAP）

```solidity
// 使用 Uniswap V3 TWAP
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";

function getPrice() public view returns (uint) {
    // 使用 TWAP 而非瞬时价格
    (int24 tick, ) = pool.slot0();
    // 计算时间加权平均
}
```

### 2. 使用多个预言机

```solidity
// 使用 Chainlink + Uniswap TWAP
function getPrice() public view returns (uint) {
    uint chainlinkPrice = getChainlinkPrice();
    uint twapPrice = getTWAPPrice();
    require(
        chainlinkPrice * 99 / 100 <= twapPrice &&
        twapPrice <= chainlinkPrice * 101 / 100,
        "Price deviation too large"
    );
    return (chainlinkPrice + twapPrice) / 2;
}
```

### 3. 闪电贷防护

```solidity
// 1. 检查 block.number 变化
// 2. 限制单笔交易金额
// 3. 使用承诺-揭示方案
```

### 4. MEV 防护

```solidity
// 1. 使用私有 mempool（Flashbots）
// 2. 使用滑点保护
// 3. 使用 MEV-Share
```

## 2024-2026 新技术点

### 1. 跨链桥攻击

```solidity
// LayerZero
// Wormhole
// 各跨链桥的攻击
```

### 2. Layer 2 攻击

```solidity
// Optimistic Rollup
// ZK Rollup
// 各 Layer 2 的攻击
```

### 3. 账户抽象攻击

```solidity
// ERC-4337
// Paymaster 漏洞
// 新的攻击模式
```

### 4. NFT 金融化

```solidity
// NFT 借贷
// NFT 碎片化
// 新的攻击模式
```

### 5. 真实世界资产（RWA）

```solidity
// RWA 代币化
// 新的攻击模式
```

### 6. 闪电贷新变种

```solidity
// 闪电贷 + 重入
// 闪电贷 + MEV
// 新的攻击组合
```

### 7. MEV 新模式

```solidity
// MEV-Share
// MEV-Boost
// 新的 MEV 模式
```

### 8. 零知识证明 DeFi

```solidity
// zk-SNARK DeFi
// 新的攻击模式
```

### 9. DAO 治理新攻击

```solidity
// 治理代币
// 投票权
// 新的攻击模式
```

### 10. AI 辅助检测

```python
# ML 辅助
# 自动检测 DeFi 漏洞
# 模式识别
```

## 工具推荐

- **Foundry** — 合约开发/测试
- **Slither** — 静态分析
- **Mythril** — 符号执行
- **Echidna** — 模糊测试
- **DeFiYield** — DeFi 安全分析
- **DefiSafety** — DeFi 审计

## 参考链接

- [DeFi Rekt](https://rekt.news/)
- [DeFi Attack Database](https://github.com/defi-attacks/defi-attacks)
- [Flash Loan Attacks](https://github.com/flashloan/flash-loan-attacks)
- [MEV Explore](https://explore.flashbots.net/)
