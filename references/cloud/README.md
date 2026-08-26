# Cloud 方向总览

Cloud（云安全）是 CTF 中分析云服务配置、容器逃逸、Kubernetes 攻击的方向。本目录按技术点拆分。

## 子路由表（症状 → 文件）

| 题目症状 | 技术点 | 文件 |
|---------|-------|------|
| Docker 容器、特权模式、挂载 | 容器逃逸 | `container-escape.md` |
| Kubernetes、Pod、Service Account | K8s 攻击 | `k8s-attacks.md` |
| AWS/GCP/Azure、元数据服务 | 云服务攻击 | `cloud-services.md` |

## Cloud 通用解题流程

### 1. 环境识别

```bash
# 容器环境
cat /proc/1/cgroup
ls /.dockerenv
cat /proc/self/mountinfo

# Kubernetes
ls /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# 云服务
curl http://169.254.169.254/latest/meta-data/  # AWS
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/  # GCP
curl -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Azure
```

### 2. 权限提升

```bash
# 容器逃逸
# 1. 特权容器
# 2. 挂载 docker.sock
# 3. 挂载 /proc
# 4. 挂载 /sys
# 5. capabilities
# 6. 内核漏洞

# K8s 提权
# 1. Service Account token
# 2. RBAC 配置错误
# 3. Pod 逃逸
# 4. 内核漏洞

# 云服务提权
# 1. IAM 配置错误
# 2. 角色链
# 3. 元数据服务
# 4. 函数权限
```

### 3. 横向移动

```bash
# 容器间
# 1. Docker 网络
# 2. K8s 网络
# 3. Service Mesh

# 云服务间
# 1. IAM 角色
# 2. 跨账户
# 3. 跨区域
```

## 工具清单

| 工具 | 用途 |
|------|------|
| kubectl | K8s CLI |
| awscli | AWS CLI |
| gcloud | GCP CLI |
| az | Azure CLI |
| docker | Docker CLI |
| cdk | 容器/K8s 渗透工具 |
| kube-hunter | K8s 漏洞扫描 |
| Peirates | K8s 渗透 |
| kubeaudit | K8s 审计 |
| Prowler | AWS 安全审计 |
| ScoutSuite | 多云审计 |

## 2024-2026 Cloud 新趋势

- **容器逃逸新 CVE**：CVE-2022-0185、CVE-2022-0492、CVE-2024-21626
- **K8s 新攻击面**：Admission Controller、Operator、CRD
- **云服务新攻击**：Lambda 注入、Functions 注入
- **Service Mesh 攻击**：Istio、Linkerd
- **Serverless 攻击**：AWS Lambda、Cloud Functions
- **多云攻击**：跨云权限提升
- **边缘计算攻击**：CDN、Edge Functions
- **AI 服务攻击**：ML 模型提取、Prompt Injection
- **量子云**：量子计算服务
- **零信任**：零信任架构攻击

具体技术细节见各文件末尾的"2024-2026 新技术点"小节。
