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

### 1. Vyper 整数溢出 PoC

```python
# Vyper < 0.3.4 没有内置的溢出检查
# @version 0.2.4

balances: HashMap[address, uint256]
token_total_supply: uint256

@external
def transfer(to: address, amount: uint256):
    # Vyper 0.2.x 不检查整数溢出！
    self.balances[msg.sender] -= amount     # 下溢：如果 amount > balance，回绕到巨大值
    self.balances[to] += amount             # 上溢：可能回绕到 0
    
@external  
def batch_transfer(recipients: DynArray[address, 100], amounts: DynArray[uint256, 100]):
    assert len(recipients) == len(amounts)
    total: uint256 = 0
    for i in range(100):
        if i >= len(recipients):
            break
        total += amounts[i]  # 这里 total 可能溢出
    assert self.balances[msg.sender] >= total  # 溢出后 total 很小，检查通过
    
    for i in range(100):
        if i >= len(recipients):
            break
        self.balances[recipients[i]] += amounts[i]
        self.balances[msg.sender] -= amounts[i]  # 逐个扣减也溢出
```

**Vyper vs Solidity 溢出对比**：
- Solidity < 0.8.0：不检查溢出（需 SafeMath）
- Solidity >= 0.8.0：内置溢出检查
- Vyper < 0.3.4：**不检查溢出**（与旧版 Solidity 类似）
- Vyper >= 0.3.4：内置溢出检查

### 2. Yul 内联汇编溢出

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract YulOverflow {
    // Solidity 0.8+ 有内置溢出检查，但 Yul 内联汇编绕过所有检查！
    
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256 result) {
        assembly {
            // Yul 的 add 不做溢出检查，即使外层是 Solidity 0.8
            result := add(a, b)
        }
    }
    
    function unsafeMul(uint256 a, uint256 b) public pure returns (uint256 result) {
        assembly {
            result := mul(a, b)
        }
    }
    
    function unsafeSub(uint256 a, uint256 b) public pure returns (uint256 result) {
        assembly {
            result := sub(a, b)
        }
    }
    
    // 更隐蔽的溢出：通过 memory 操作
    function unsafeStoreOverflow(uint256 value) public pure returns (uint256) {
        assembly {
            // 分配内存
            let ptr := mload(0x40)
            // 将 value 强制存入，忽略类型安全
            mstore(ptr, value)
            // 加上一个大数后读取
            let big := add(ptr, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
            // big 发生下溢，指向低地址内存，可能读到敏感数据
            let leaked := mload(big)
            return(0, leaked)
        }
    }
    
    // 真实案例：某些 DeFi 协议在 Yul 优化器生成的代码中
    // 使用 unchecked 的算术运算进行 gas 优化
    function optimizedCounter(uint256 x) external pure returns (uint256) {
        assembly {
            // 优化器可能将整个函数编译为纯 Yul
            // 使用 switch 而非 if 节省 gas
            switch x
            case 0 { x := 1 }
            default {
                // 如果 x == type(uint256).max，则 x + 1 溢出
                x := add(x, 1)  // 没有溢出检查！
            }
        }
        return x;
    }
}
```

**攻击场景**：审计时容易忽略 `assembly {}` 块中的运算。很多审计工具（如 Slither）对 Yul 的分析能力有限。

### 3. Solidity 0.8 unchecked 绕过

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedBypass {
    // 开发者经常在 "gas 优化" 中错误使用 unchecked
    
    mapping(address => uint256) public balances;
    mapping(address => uint256) public allowances;
    
    // ❌ 错误：在余额扣减中使用 unchecked
    function unsafeTransfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // 开发者以为已经检查过了，用 unchecked 节省 gas
        // 但多线程/重入场景下，余额可能已经变化！
        unchecked {
            balances[msg.sender] -= amount;
            balances[to] += amount;  // 如果 to == msg.sender，total 也不对
        }
    }
    
    // ❌ 错误：在循环中 unchecked 导致 index 溢出
    function unsafeBatchProcess(address[] calldata users, uint256[] calldata amounts) external {
        uint256 total = 0;
        
        // 开发者以为 amounts 都是小值，不会溢出
        unchecked {
            for (uint256 i = 0; i < users.length; i++) {
                total += amounts[i];  // 如果 amounts 被恶意构造，total 溢出
            }
        }
        
        require(balances[msg.sender] >= total);
        balances[msg.sender] -= total;
        
        unchecked {
            for (uint256 i = 0; i < users.length; i++) {
                balances[users[i]] += amounts[i];  // 每个加法也可能溢出
            }
        }
    }
    
    // ❌ 更隐蔽：类型转换 + unchecked
    function unsafeDowncast(uint256 bigValue) external pure returns (uint8) {
        // 开发者先检查范围，然后 unchecked 转换
        require(bigValue <= 255);
        
        uint256 temp = bigValue * 1000;  // 先放大
        
        unchecked {
            // 此时 temp 可能已经溢出（如果 bigValue 不是 0）
            // unchecked 跳过了乘法溢出检查
        }
        
        return uint8(bigValue);  // Solidity 0.8 的类型转换本身会检查
    }
    
    // ❌ 实际 DeFi 漏洞：percentage 计算中 unchecked 溢出
    function calculateReward(uint256 balance, uint256 rate) external pure returns (uint256) {
        unchecked {
            // rate 是 basis points (10000 = 100%)
            // balance * rate 可能溢出
            // 开发者以为 rate < 10000，不会溢出
            // 但外部调用者可以传入任意大值
            return balance * rate / 10000;
        }
    }
}
```

### 4. SafeMath 绕过

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "@openzeppelin/contracts/math/SafeMath.sol";

contract SafeMathBypass {
    using SafeMath for uint256;
    
    mapping(address => uint256) public balances;
    
    // 方法 1：绕过 SafeMath 使用原生运算符
    function bypassDirect(uint256 amount) external {
        // SafeMath 只对使用 .add() .sub() 方法调用生效
        // 原生 +/- 运算符不经过 SafeMath
        balances[msg.sender] -= amount;  // 直接溢出！
    }
    
    // 方法 2：在 SafeMath 之后的逻辑中溢出
    function bypassAfterSafeMath(uint256 amount) external {
        // SafeMath 安全扣减
        balances[msg.sender] = balances[msg.sender].sub(amount);
        
        // 但在后续逻辑中未使用 SafeMath
        uint256 fee = amount * 10 / 100;  // 如果 amount 极大，溢出
        balances[msg.sender] -= fee;       // fee 可能是 0，导致少扣
    }
    
    // 方法 3：利用 SafeMath 不检查除法精度
    function precisionLoss(uint256 numerator, uint256 denominator) external pure returns (uint256) {
        // SafeMath 的 div 只检查除零，不检查精度损失
        // 如果 numerator = 5, denominator = 3
        // 结果是 1 而非 1.666，精度损失被忽略
        return numerator.safeDiv(denominator);
    }
    
    // 方法 4：SafeMath.mul 溢出检测的局限性
    function mulBypass(uint256 a, uint256 b) external pure returns (uint256) {
        // SafeMath.mul 会检查 a*b 是否溢出
        // 但通过多次小值累加可以绕过
        uint256 result = 0;
        // 如果 a = 2^128, b = 2^129
        // a * b = 2^257 溢出，SafeMath 会 revert
        // 但如果 b 以 1 为步长累加，每次都安全
        // 实际上这仍然是 a * b，只是换了一种方式
        // 真正的绕过是：使用 assembly 或类型转换
        assembly {
            result := mul(a, b)  // 直接在 assembly 中绕过 SafeMath
        }
        return result;
    }
    
    // 方法 5：类型转换绕过
    function typeCastBypass(uint256 value) external pure returns (uint8) {
        // SafeMath 不处理类型转换
        // uint256 转 uint8 在 Solidity 0.7 中不检查溢出
        return uint8(value);  // 256 → 0, 512 → 0, 257 → 1
        
        // 在 Solidity 0.8 中这会自动 revert
        // 但在 0.7 中是静默截断
    }
}
```

### 5. 时间戳与区块号溢出

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TimestampOverflow {
    // 时间戳相关溢出（2038 年问题和极端值）
    uint256 public deadline;
    
    function setDeadline(uint256 hoursFromNow) external {
        // block.timestamp 是 uint256，不会在 2038 年溢出
        // 但如果 hoursFromNow 是极大值：
        unchecked {
            deadline = block.timestamp + hoursFromNow * 3600;  // 可能溢出
        }
    }
    
    function isExpired() external view returns (bool) {
        return block.timestamp > deadline;
    }
    
    // 区块号溢出
    function blockNumberArithmetic(uint256 targetBlock) external view returns (bool) {
        unchecked {
            // targetBlock - block.number 如果 targetBlock < block.number
            // 下溢得到极大值，导致 "永远不会到达" 的逻辑被绕过
            uint256 diff = targetBlock - block.number;
            return diff < 1000;  // 如果下溢，diff 极大，返回 false
        }
    }
}
```

### 6. 除法精度与中间值溢出

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PrecisionOverflow {
    // 先乘后除 vs 先除后乘 的精度与溢出权衡
    
    // ❌ 先乘后除：可能溢出但精度高
    function unsafeMulDiv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return a * b / c;  // a*b 可能溢出
    }
    
    // ✅ 先除后乘：不溢出但精度损失
    function safeDivMul(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return (a / c) * b;  // a/c 精度损失
    }
    
    // ✅ 最佳方案：使用 mulDiv（OpenZeppelin Math 库）
    // function mulDiv(uint256 x, uint256 y, uint256 denominator) 内部用 512 位运算
    
    // 实际漏洞：代币分配中的精度 + 溢出组合
    function distributeReward(uint256 totalReward, uint256 share, uint256 totalShares) 
        internal pure returns (uint256) 
    {
        // 如果 totalReward * share > 2^256，溢出归零
        // 然后除以 totalShares 得到 0
        // 用户应得的奖励消失
        unchecked {
            return totalReward * share / totalShares;
        }
    }
}
```

## 2024-2026 高级溢出攻击

### 1. Yul 编译器生成代码中的隐蔽溢出

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract YulCompilerBypass {
    // Solidity 优化器生成的 Yul 代码可能使用 unchecked 运算
    // 手动审计时容易忽略
    
    // 场景：编译器优化将 checked 代码优化为 unchecked
    // 优化级别 -O2 或 -O3 时可能发生
    
    function optimizedSwap(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) external pure returns (uint256 amountOut) {
        // 编译器优化后的 Yul 可能是：
        // amountInWithFee := mul(amountIn, 997)
        // numerator := mul(amountInWithFee, reserveOut)
        // denominator := add(mul(reserveIn, 1000), amountInWithFee)
        // amountOut := div(numerator, denominator)
        //
        // 如果 optimizele 启用 --yul-optimizations，乘法可能变为 unchecked
        
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        amountOut = numerator / denominator;
    }
    
    // 检查：使用 `forge inspect YulCompilerBypass ir-optimized`
    // 查看编译器实际生成的 Yul 代码，确认是否有 unchecked 操作
}
```

### 2. Yul assembly 溢出完整 PoC

```solidity
// SPDX-License-Identifier:MIT
pragma solidity ^0.8.0;

contract YulOverflowPoC {
    // 真实场景：审计中发现的 Yul 溢出
    // 来源：2024 年多个 DeFi 协议审计报告
    
    mapping(address => uint256) public poolBalances;
    mapping(address => uint256) public userShares;
    uint256 public totalShares;
    
    // 用户存款 → 计算份额
    function deposit(uint256 amount) external {
        uint256 shares;
        assembly {
            // 计算：shares = amount * totalShares / poolBalances[msg.sender]
            // 问题：amount * totalShares 可能溢出
            let poolBal := sload(add(poolBalances.slot, mul(msg.sender, 32)))
            let totShares := sload(totalShares.slot)
            
            // ⚠️ mul 不检查溢出！
            let numerator := mul(amount, totShares)
            // 如果 amount 极大，numerator 溢出为小值
            // 导致 shares 计算错误
            
            // 正确做法应使用 mulmod 检查：
            // let hi := mulmod(amount, totShares, 0)
            // if hi { revert(0, 0) }  // hi != 0 说明溢出
            
            let denom := add(poolBal, amount)
            shares := div(numerator, denom)
            
            // 存储 shares
            sstore(add(userShares.slot, mul(msg.sender, 32)), shares)
            sstore(totalShares.slot, add(totShares, shares))
            sstore(add(poolBalances.slot, mul(msg.sender, 32)), add(poolBal, amount))
        }
    }
    
    // 防御：使用 mulmod 进行溢出检查
    function safeDeposit(uint256 amount) external {
        uint256 shares;
        assembly {
            let poolBal := sload(add(poolBalances.slot, mul(msg.sender, 32)))
            let totShares := sload(totalShares.slot)
            
            // ✅ 检查溢出
            let hi := mulmod(amount, totShares, 0)
            if hi { revert(0, 0) }
            
            let numerator := mul(amount, totShares)
            let denom := add(poolBal, amount)
            shares := div(numerator, denom)
            
            sstore(add(userShares.slot, mul(msg.sender, 32)), shares)
            sstore(totalShares.slot, add(totShares, shares))
            sstore(add(poolBalances.slot, mul(msg.sender, 32)), add(poolBal, amount))
        }
    }
}
```

### 3. Solidity 0.8 unchecked 在 DeFi 协议中的实战绕过

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract UncheckedDeFiBypass {
    IERC20 public token;
    mapping(address => uint256) public staked;
    mapping(address => uint256) public rewardDebt;
    uint256 public accRewardPerShare;  // 累积每份奖励
    uint256 public totalStaked;
    
    constructor(address _token) {
        token = IERC20(_token);
    }
    
    // 实际漏洞：rewardDebt 使用 unchecked 导致用户可重复领取奖励
    function claimReward() external {
        uint256 pending = (staked[msg.sender] * accRewardPerShare) / 1e12 - rewardDebt[msg.sender];
        
        // ❌ 开发者为了 gas 优化使用 unchecked
        // 但如果 pending 因为乘法溢出变成巨大值...
        unchecked {
            rewardDebt[msg.sender] = staked[msg.sender] * accRewardPerShare / 1e12;
        }
        
        // 多次调用 claimReward()，如果 accRewardPerShare 更新逻辑有问题
        // rewardDebt 被 unchecked 更新可能变成 0 或错误值
        // 导致 pending 每次都算出正数
        
        if (pending > 0) {
            token.transfer(msg.sender, pending);
        }
    }
    
    // 攻击：结合闪电贷
    // 1. 借闪电贷大量代币
    // 2. stake 大量代币 → accRewardPerShare 激增
    // 3. claimReward → pending 溢出得到巨量奖励
    // 4. unstake + 归还闪电贷
    // 5. 净赚：被膨胀的奖励
}
```

### 4. SafeMath 绕过：assembly 直接运算

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "@openzeppelin/contracts/math/SafeMath.sol";

contract SafeMathAssemblyBypass {
    using SafeMath for uint256;
    
    mapping(address => uint256) public balances;
    
    // 所有可见的运算都用了 SafeMath
    function deposit() external payable {
        balances[msg.sender] = balances[msg.sender].add(msg.value);
    }
    
    function withdraw(uint256 amount) external {
        balances[msg.sender] = balances[msg.sender].sub(amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
    
    // 但是！管理函数直接用 assembly 操作 storage
    // 绕过 SafeMath 且审计时容易遗漏
    function emergencyWithdraw(address user) external {
        // 假设这是 "紧急提款" 功能
        // 开发者直接用 assembly 操作 storage（以为更快）
        uint256 bal;
        assembly {
            bal := sload(add(balances.slot, mul(user, 32)))
            
            // ❌ 没有 SafeMath！
            // 如果外部逻辑导致 balances[user] 被多次修改
            // 这里的 bal 值可能已经不一致
            
            sstore(add(balances.slot, mul(user, 32)), 0)
        }
        
        (bool success, ) = user.call{value: bal}("");
        require(success);
    }
    
    // 防御：对 storage 直接操作也要使用溢出检查
    function safeEmergencyWithdraw(address user) external {
        uint256 bal;
        assembly {
            bal := sload(add(balances.slot, mul(user, 32)))
            sstore(add(balances.slot, mul(user, 32)), 0)
            
            // ✅ 检查 bal > 0（防止重入等场景下的 double-withdraw）
            if iszero(bal) { revert(0, 0) }
        }
        
        (bool success, ) = user.call{value: bal}("");
        require(success);
    }
}
```

### 5. ERC-4626 金库溢出攻击

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ERC-4626 标准金库的溢出漏洞
// 2023-2024 年多个金库协议被此漏洞攻击

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract VulnerableVault {
    IERC20 public asset;
    uint256 public totalShares;
    
    constructor(address _asset) {
        asset = IERC20(_asset);
    }
    
    // 存入资产 → 铸造份额
    function deposit(uint256 assets) external returns (uint256 shares) {
        uint256 totalAssets = asset.balanceOf(address(this));
        
        if (totalAssets == 0 || totalShares == 0) {
            shares = assets;
        } else {
            // ❌ 漏洞：这里先除后乘，但如果用乘后除呢？
            // shares = assets * totalShares / totalAssets
            // 如果 assets * totalAssets 溢出...
            shares = (assets * totalShares) / totalAssets;
        }
        
        totalShares += shares;
        asset.transferFrom(msg.sender, address(this), assets);
    }
    
    // 取出资产 → 销毁份额
    function withdraw(uint256 shares) external returns (uint256 assets) {
        uint256 totalAssets = asset.balanceOf(address(this));
        
        assets = (shares * totalAssets) / totalShares;
        
        // 攻击：
        // 1. 先 mint 1 wei 的份额（ deposits 1 wei assets）
        // 2. 直接向合约转入巨量 assets（不通过 deposit）
        // 3. 此时 totalAssets 巨大但 totalShares 只有 1
        // 4. withdraw(1) → 得到全部 assets
        // 或者：
        // 1. 利用 share 精度为 0 的边界情况
        // 2. shares = (assets * totalShares) / totalAssets
        // 3. 如果 totalAssets >> assets * totalShares，shares = 0
        // 4. 铸造了 0 份额但扣除了 assets
        
        totalShares -= shares;
        asset.transfer(msg.sender, assets);
    }
}
```

> **防御**：使用 OpenZeppelin 的 ERC4626 实现，其中包含了对各种溢出/精度边界的正确处理。

## 工具推荐

- **Slither** — 静态分析
- **Mythril** — 符号执行
- **Echidna** — 模糊测试
- **manticore** — 符号执行

## 参考链接

- [SWC-101: Integer Overflow](https://swcregistry.io/docs/SWC-101)
- [BEC Token Hack](https://www.peckshield.com/2018/04/25/bec/)
- [SafeMath](https://docs.openzeppelin.com/contracts/3.x/api/utils#SafeMath)
