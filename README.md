# OSS_Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Author](https://img.shields.io/badge/Author-sjdalu-orange)
![Version](https://img.shields.io/badge/Version-v2.2.0-informational)

OSS_Scanner 是一款**多厂商 OSS 存储桶漏洞扫描工具**，支持阿里云 OSS、腾讯云 COS、华为云 OBS、AWS S3、GCP Cloud Storage、Azure Blob，检测敏感文件泄露、匿名上传 / 删除、CORS 配置过宽、策略过度宽松等风险，帮助安全测试人员在授权范围内快速发现存储桶配置问题。

## ⚠️ 请先读这一条：写操作默认关闭

本工具通过 **PUT / POST / DELETE 与修改 ACL** 来验证「匿名写入 / 删除」类漏洞，这些操作会在目标桶里产生真实对象。为了不越过授权范围，v2.0 引入了总闸门：

```ini
allow_intrusive_write = false   # 默认值
```

- **默认（false）**：所有写操作与 ACL 修改一律跳过，并在日志中明确说明跳过了哪些检查。
- **改为 true**：放行写操作。具体执行哪些仍由 `scan_put_upload`、`scan_delete_perm`、`scan_acl_write` 等开关逐项控制。
- 所有写入的测试对象都会在上传后立即清理；GCP 的 Bucket ACL 检测在验证后会立刻恢复为私有。

> 旧版本没有这个闸门：即使把 `scan_put_upload` 全设为 false，阿里云扫描仍会向目标桶上传文件并尝试改 ACL。v2.0 修正了这一点。

## 📋 功能特性

| 功能模块         | 检测能力                                                     |
| ---------------- | ------------------------------------------------------------ |
| 敏感文件扫描     | 密钥文件（`.env`、`id_rsa`）、数据库备份（`.sql`、`.bak`）、配置文件（`wp-config.php`）等 |
| 写权限检测       | 公开可列目录、匿名 PUT 上传、匿名 POST 表单上传、匿名 DELETE、对象 / Bucket ACL 可写 |
| 策略与配置检查   | Bucket 策略匿名授权、策略管理员权限未限制来源、CORS 过宽、未开启日志转存 |
| ACL 授权项检查   | `AllUsers`（全网公开）、`AuthenticatedUsers`（任意已认证用户）这类过宽授权 |
| 版本控制检查     | 历史版本能否取回（删除文件不等于数据消失）、是否缺少 MFA 删除保护 |
| 其他只读检查     | 静态网站托管、防盗链（Referer 白名单）、跨账号复制规则       |
| 加密检查         | 未启用服务端加密、使用 AES256 而非 KMS、使用 KMS 但未使用自定义主密钥 |
| 信息泄露         | 访问日志泄露、响应头泄露存储元信息、明文 HTTP 可访问         |
| **临时凭证认证** | 用 STS 临时凭证签名请求，以认证身份扫描，看到匿名看不到的配置 |
| **区域自动发现** | 从 `x-amz-bucket-region` 等响应头校正区域，避免扫错地址      |
| **PoC 生成**     | 每条风险附一条可复制执行的 curl 命令（认证态用占位符，不泄令牌） |
| AI 研判          | 执行摘要与修复计划、误报降噪、泄露内容凭据识别与脱敏         |
| 报告生成         | Text / JSON / HTML 三种格式；每条结果带状态码、Content-Type 与响应体片段作为证据 |
| 多厂商           | 6 家：阿里云 OSS、腾讯云 COS、华为云 OBS、AWS S3、GCP、Azure Blob |
| 端点自动解析     | 可从 URL 自动识别厂商与区域，无需逐项手填                     |
| 可控请求速率     | 全局按主机令牌桶限速，线程数与实际请求速率解耦                 |

## 🛠️ 安装

```bash
git clone https://github.com/bitboy-sys/OSS_scanner.git
cd OSS_Scanner
pip install -r requirements.txt
```

运行测试（可选）：

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

### 依赖说明

```
requests>=2.31.0
urllib3>=2.0.7
colorama>=0.4.6
tqdm>=4.66.1
jinja2>=3.1.2
```

## 🚀 快速使用

### 扫描单个 Bucket

```bash
python main.py \
  --cloud aliyun \
  --region ap-southeast-1 \
  --bucket 你的测试Bucket名称 \
  --output html \
  --output-file ./reports/aliyun_scan.html
```

### 从端点地址自动识别厂商与区域

```bash
python main.py --hostid-url https://bucket.oss-cn-beijing.aliyuncs.com --output html
```

`--hostid-url` 支持三种输入，会自动选择最合适的方式：

1. 直接是存储端点 → 解析出厂商、Bucket、区域（`bucket.oss-cn-beijing.aliyuncs.com`）
2. 存储域名的 path-style 形式 → 从路径取 Bucket
3. 普通网页 → 抓取页面中的 `<HostId>` 标签再解析

若把地址写进配置的 `AUTO_EXTRACT.hostid_url`，甚至可以省略该参数。

### 批量扫描

```bash
python main.py \
  --cloud tencent \
  --region ap-guangzhou \
  --bucket-file ./bucket_list.txt \
  --thread 10 \
  --output json \
  --output-file ./reports/tencent_batch_scan.json \
  --progress
```

### 关键参数

| 参数            | 作用                        | 必填   | 示例                                             |
| --------------- | --------------------------- | ------ | ------------------------------------------------ |
| `--cloud`       | 目标云厂商                  | 条件   | `aliyun`/`tencent`/`huawei`/`aws`/`gcp`/`azure`  |
| `--region`      | 存储桶区域                  | 条件   | 阿里云 `ap-southeast-1`；AWS `us-east-1`         |
| `--bucket`      | 单个 Bucket / 容器名称      | 三选一 | `my-test-bucket`                                 |
| `--bucket-list` | 多个 Bucket（逗号分隔）     | 三选一 | `b1,b2,b3`                                       |
| `--bucket-file` | Bucket 列表文件             | 三选一 | `./bucket_list.txt`                              |
| `--account`     | Azure 存储账户名            | azure 必填 | `mystorageaccount`                           |
| `--sts-ak` / `--sts-sk` / `--sts-token` | 临时凭证三元组 | 否 | 建议改用环境变量 |
| `--sts-file`    | STS 凭证 JSON 文件（AssumeRole 响应原样） | 否 | `./role-session.json` |
| `--no-poc`      | 报告中不生成 PoC 命令       | 否     | 无值                                             |
| `--endpoint-url` | 端点或网页地址（同 `--hostid-url`） | 否 | `https://bucket.s3.us-east-1.amazonaws.com`  |
| `--tencent-appid` | 腾讯云 APPID              | 否     | `1250000000`                                     |
| `--output`      | 输出格式                    | 否     | `text`（默认）/`json`/`html`                     |
| `--output-file` | 结果保存路径（会自动创建目录） | 否  | `./reports/scan_report.html`                     |
| `--thread`      | 并发扫描的 Bucket 数        | 否     | `5`（默认）                                      |
| `--progress`    | 显示扫描进度条              | 否     | 无值                                             |
| `--proxy`       | 代理地址                    | 否     | `http://127.0.0.1:8080`                          |
| `--alert`       | 严重漏洞告警方式            | 否     | `dingtalk`/`email`                               |
| `--debug`       | 输出调试日志                | 否     | 无值                                             |

`--cloud` 与 `--region` 在使用 `--bucket*` 时才需要（gcp / azure 除外，二者不需要区域）；
使用 `--endpoint-url` / `--hostid-url` 时程序会自行推断。

## ⚙️ 配置文件说明

核心配置文件为 `config/config.ini`。

### 请求行为

```ini
request_timeout = 10     # 单次请求超时（秒）
request_interval = 0.3   # 同一主机两次请求的最小间隔（秒），全局生效
request_burst = 5        # 每主机允许的突发请求数（令牌桶容量）
max_retry = 2            # 幂等请求（HEAD/GET/OPTIONS）失败重试次数
https_only = false       # true 时只使用 HTTPS
```

`request_interval` 是**全局按主机**限速，与 `--thread` 无关：调大线程数不会像旧版那样成倍放大实际请求速率。突发容量用完后按 `1/request_interval` 的速率补充令牌。

> 旧版是「每个线程各自 sleep 1 秒、默认 5 线程」，实际聚合速率可达 5 请求/秒。默认 0.3（约 3.3 请求/秒）比旧行为更保守，同时把单桶耗时从 100 秒以上降到 15 秒以内。想更保守就调大，想更快就调小（`0` 表示不限速）。

### 写操作总闸门与检测开关

```ini
allow_intrusive_write = false   # 写操作总闸门，默认关闭

# 只读检查
scan_cors = true
scan_logs = true
scan_directory_traversal = true
scan_sensitive_headers = true
scan_bucket_policy = true
scan_kms_encryption = true

# 写入类检查：除下方开关外，还需 allow_intrusive_write = true
scan_put_upload = true
scan_post_upload = true
scan_delete_perm = true
scan_acl_write = true
scan_acl_read = true
scan_blob_public_access = true

# 尚未实现，启用会被跳过并给出提示
scan_version_leak = false
```

### URL 模板

模板统一用 **https** 书写，明文 HTTP 形式由程序自动推导（仅在 `https_only = false` 时才会探测），因此不再需要单独的 http 模板。

```ini
[CLOUD_TEMPLATES]
aliyun_https = https://{bucket}.oss-{region}.aliyuncs.com
tencent_https = https://{bucket}-{appid}.cos.{region}.myqcloud.com
tencent_https_no_appid = https://{bucket}.cos.{region}.myqcloud.com
huawei_https = https://{bucket}.obs.{region}.myhuaweicloud.com
aws_https = https://{bucket}.s3.{region}.amazonaws.com
gcp_https = https://{bucket}.storage.googleapis.com
azure_blob_url = https://{account}.blob.core.windows.net/{container}
```

### 敏感路径

```ini
[SENSITIVE_PATHS]
key_paths = .env, credentials.json, access_key.txt, secret_key.txt, id_rsa, private_key.pem
db_paths = backup/database.sql, db/dump.sql, database_backup.zip, db.bak, sql.gz
config_paths = config/database.yml, conf/app.conf, wp-config.php, src/config.php
log_paths = logs/app.log, access.log, error.log
src_paths = wwwroot/.git/config, backup/site.tar.gz, src.zip
```

逗号分隔即可，条目内的空格会被自动处理。

> 修正说明：旧版把配置按 `,` 切开后只对路径做了 `strip`，却拿**未 strip** 的配置项去比对，导致每类里除第一条外全部被降级为最低等级——`id_rsa`、`private_key.pem`、`credentials.json`、`db.bak`、`wp-config.php` 都曾只报「低危」。v2.0 已修正。

## 📊 风险项清单

每条结果都带稳定的 `risk_id`（可直接用于 CI 断言）与严重度。完整元数据（中文标题、修复建议、合规映射）见 `core/risk_analyzer.py`。

| 严重度 | risk_id                                                    | 说明                             |
| ------ | ---------------------------------------------------------- | -------------------------------- |
| 严重   | `KEY_FILE_EXPOSED`                                         | 密钥文件可匿名访问               |
| 严重   | `DB_BACKUP_EXPOSED`                                        | 数据库备份可匿名访问             |
| 严重   | `ANON_WRITE_PUT` / `ANON_WRITE_POST`                       | 允许匿名上传                     |
| 严重   | `ANON_DELETE`                                              | 允许匿名删除对象                 |
| 严重   | `POLICY_ANON_WRITE`                                        | Bucket 策略允许匿名写入或删除    |
| 高危   | `PUBLIC_LIST`                                              | 公开可列目录                     |
| 高危   | `LOG_EXPOSED`                                              | 访问日志可匿名读取               |
| 高危   | `ACL_WRITABLE`                                             | 对象或 Bucket ACL 可匿名写入     |
| 高危   | `POLICY_ANON_READ` / `POLICY_ANON_POLICY_READ`             | 策略允许匿名读取 / 读取策略本身  |
| 高危   | `POLICY_ADMIN_UNBOUNDED`                                   | 管理员权限未限制来源             |
| 高危   | `NO_SSE`                                                   | 未启用服务端加密                 |
| 高危   | `ACL_PUBLIC_GRANT` / `ACL_AUTHENTICATED_GRANT`              | ACL 授予全网 / 任意已认证用户    |
| 高危   | `DELETED_OBJECT_RECOVERABLE`                                | 已删除的敏感对象可从历史版本恢复 |
| 高危   | `CROSS_ACCOUNT_REPLICATION`                                 | 跨账号复制可能造成数据外流       |
| 中危   | `CONFIG_FILE_EXPOSED`                                      | 配置文件可匿名访问               |
| 中危   | `ACL_READABLE` / `BLOB_PUBLIC_ACCESS`                      | 对象 ACL 可读 / Blob 匿名公开    |
| 中危   | `CORS_WILDCARD` / `DIRECTORY_TRAVERSAL`                    | CORS 过宽 / 目录遍历             |
| 中危   | `LOGGING_DISABLED`                                         | 未开启访问日志转存               |
| 中危   | `ENCRYPTION_AES_NOT_KMS` / `ENCRYPTION_NO_CUSTOM_KEY`      | 加密方式不足                     |
| 中危   | `REFERER_UNRESTRICTED` / `STATIC_WEBSITE_ENABLED`           | 未配防盗链 / 开启静态网站托管    |
| 低危   | `VERSIONING_WITHOUT_MFA_DELETE`                             | 未启用 MFA 删除保护              |
| 低危   | `OTHER_FILE_EXPOSED` / `SENSITIVE_HEADERS` / `HTTP_ENABLED` | 其他敏感路径 / 元信息头 / 明文 HTTP |
| 信息   | `BUCKET_NOT_FOUND` / `BUCKET_EXISTS_NO_ACCESS`             | 目标不存在 / 存在但不可访问（非漏洞） |
| 信息   | `REGION_DISCOVERED`                                        | 已按响应头自动校正区域           |
| 错误   | `AUTH_ERROR`                                               | 认证信息不可用                   |
| 错误   | `SCAN_ERROR`                                               | 扫描过程发生错误                 |

## 🔑 临时凭证（STS）认证扫描

匿名扫描只能看到「对全网开放」的配置。很多真实问题——ACL 把权限授予了
`AuthenticatedUsers`、策略只对已认证主体开放、历史版本里躺着已删除的密钥——
**只有拿到凭证才看得到**。工具支持用各厂商 STS 签发的临时凭证以认证身份扫描。

### 用法

推荐用环境变量，避免密钥落在配置文件或命令历史里：

```bash
export OSS_SCANNER_STS_AK=LTAI5t...
export OSS_SCANNER_STS_SK=...
export OSS_SCANNER_STS_TOKEN=...
python main.py --cloud aliyun --region cn-beijing --bucket 目标桶 --output html
```

也可以走命令行（注意命令历史会留存）、凭证文件或配置：

```bash
# AssumeRole 接口的响应原样保存即可，程序会自动取出 Credentials 字段
python main.py --cloud aws --region us-east-1 --bucket b --sts-file ./role-session.json
```

优先级：`--sts-ak/--sts-sk/--sts-token` > 环境变量 > `--sts-file` /
`[STS] credential_file` > `[STS]` 节点。

### 支持的签名方案

| 厂商 | 签名 | 令牌头 |
| ---- | ---- | ------ |
| AWS S3 | SigV4（已用 AWS 官方测试向量校验） | `x-amz-security-token` |
| 华为云 OBS | SigV4（S3 兼容） | `x-obs-security-token` |
| GCP | SigV4（service 为 `storage`，区域 `auto`） | `x-goog-security-token` |
| 阿里云 OSS | OSS 签名（HMAC-SHA1，含子资源） | `x-oss-security-token` |
| 腾讯云 COS | q-sign 签名 | `x-cos-security-token` |
| Azure | 不支持 AK/SK，需改用 SAS | — |

### 安全约束

- 持有凭证后报错、日志、报告里只会出现掩码后的 AccessKeyId（`LTAI****`），
  AccessKeySecret 与 SecurityToken 从不落盘；凭证对象的 `repr` 也已改造，不会因误打印而泄漏。
- 生成的 PoC 用 `$OSS_SCANNER_STS_TOKEN` 占位符，不写入真实令牌——报告经常被转发和归档。
- 凭证过期、只有一半字段、厂商不支持签名等情况会明确报错，**不会静默退化成匿名扫描**。
- 所有结果都带 `auth_mode` 字段（`anonymous` / `authenticated`），报告里认证态条目会标注
  「认证态发现」，便于区分「公开可访问」与「该凭证可访问」。

## 🎯 PoC 复现命令

每条风险会附一条可直接执行的命令，例如：

```bash
# 列表类
curl -sS -i --max-time 15 'https://b.oss-cn-beijing.aliyuncs.com?list-type=2&max-keys=20'
# 文件泄露类（只取前 200 字节，避免把几个 G 的备份拉下来）
curl -sS -i --max-time 15 'https://b.oss-cn-beijing.aliyuncs.com/.env' | head -c 200
# 目录遍历类必须带 --path-as-is，否则 curl 会把 ../ 折叠掉，复现不出来
curl -sS -i --max-time 15 --path-as-is 'https://b.oss-cn-beijing.aliyuncs.com/../../etc/passwd'
```

写操作类（PUT/POST/DELETE）的命令会带上「这会真的修改目标」的提示。
用 `--no-poc` 可关闭生成。

## 🤖 AI 研判能力（可选，默认关闭）

AI 只产出**建议**，不改变扫描结论；任何一步失败都会降级为「无 AI 结论」，本地报告照常产出。

### 三个步骤

| 步骤 | 作用 | 附加字段 |
| ---- | ---- | -------- |
| `report` | 生成执行摘要、按业务影响排序的风险优先级、带云控制台操作路径的修复计划 | 报告级 `ai_summary` |
| `analyze` | 误报降噪：逐条判断真伪并给出依据 | `ai_confidence`、`ai_reason`、`ai_false_positive_likely` |
| `classify` | 泄露内容分级：识别文件里到底是什么凭据、是否像可用凭据、影响什么系统 | `verified_credentials[]` |

`classify` 的处理链路是**本地正则先筛、只把掩码片段发给模型**：先在采集到的响应体里查找
AccessKey / 私钥头 / JWT / 连接串口令等形态，命中后发送的也只是形如 `LTAI****`、`user:****@host`
的掩码内容。原始凭据从不离开本机，报告里也不会出现（**但证据字段本身是目标返回的原文，
报告文件含未脱敏内容，请妥善保管**）。

### 启用方式

```bash
# 本地 Ollama（推荐，数据不出本机）
pip install -r requirements.txt
ollama pull qwen2.5:7b
python main.py --bucket 目标桶 --cloud aliyun --region cn-beijing --ai all --output html

# 只跑报告研判
python main.py --bucket 目标桶 --cloud aliyun --region cn-beijing --ai report
```

配置位于 `config/config.ini` 的 `[AI_CONFIG]`。**切换厂商只需要改 `provider` 一行**，
端点与模型会自动跟随：

```ini
[AI_CONFIG]
enabled = false
provider = ollama          # ollama / deepseek / openai / dashscope / zhipu / moonshot / siliconflow / custom
base_url =                 # 留空则用该预设的默认端点
model =                    # 留空则用该预设的默认模型
api_key =                  # 留空则从环境变量读取
timeout = 60
features = report,analyze,classify
redact = true
cache = ai_cache.json
ack_data_egress = false
```

| 预设 | 端点 | 默认模型 | 密钥环境变量 |
| ---- | ---- | -------- | ------------ |
| `ollama` | `http://127.0.0.1:11434/v1` | `qwen2.5:7b` | 无需 |
| `deepseek` | `https://api.deepseek.com/v1` | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| `openai` | `https://api.openai.com/v1` | `gpt-4o-mini` | `OPENAI_API_KEY` |
| `dashscope` | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-plus` | `DASHSCOPE_API_KEY` |
| `zhipu` | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-flash` | `ZHIPUAI_API_KEY` |
| `moonshot` | `https://api.moonshot.cn/v1` | `moonshot-v1-8k` | `MOONSHOT_API_KEY` |
| `siliconflow` | `https://api.siliconflow.cn/v1` | `Qwen/Qwen2.5-7B-Instruct` | `SILICONFLOW_API_KEY` |

密钥可以放在配置里，也可以放环境变量：任意厂商都认通用变量
`OSS_SCANNER_AI_KEY`，也可用上表里各自的约定变量。命令行可以临时切换：

```bash
# 用 DeepSeek 跑一次研判（密钥已在环境变量里）
export DEEPSEEK_API_KEY=sk-...
python main.py --bucket 目标桶 --cloud aliyun --region cn-beijing \
  --ai-provider deepseek --ai all --i-accept-ai-egress --output html
```

用云端厂商时记得加 `--i-accept-ai-egress`（或把 `ack_data_egress` 设为 `true`），
否则会被数据外发闸门拦下——这是刻意设计，见下节。

提示词放在 `config/prompts/{report,analyze,classify}.txt`，可以直接改，不需要动代码；
文件缺失时回退到内置版本。

### 数据外发闸门

这是授权渗透工具，把目标地址与泄露内容发送给第三方模型可能超出授权测试范围。因此当
`base_url` 不是本机地址时，程序会**拒绝调用**并提示：

```
AI 端点不是本机地址，可能将目标地址与泄露内容发送给第三方。
确认已获授权后，设置 [AI_CONFIG] ack_data_egress = true 或加 --i-accept-ai-egress
```

确认授权范围允许后再开启。开启 `redact` 时桶名会被替换为短哈希，保留厂商与区域信息。

### 相关参数

| 参数 | 作用 |
| ---- | ---- |
| `--ai off` / `report` / `analyze` / `classify` / `all` | 指定本次运行的 AI 步骤；`off` 强制关闭，`all` 启用全部 |
| `--ai-provider` | 临时切换 AI 厂商预设（如 `deepseek`） |
| `--ai-base-url` | 覆盖配置中的端点 |
| `--i-accept-ai-egress` | 确认允许发送到非本机端点 |

## 🧪 测试

```bash
python -m pytest tests/ -q
```

测试完全离线运行：`tests/conftest.py` 起了一个可编程的本地「假 OSS 服务」（同时模拟 OpenAI 兼容端点），覆盖端点解析、敏感路径分级、写操作闸门、策略与加密判定、AI 脱敏与外发闸门、三种报告输出，以及单桶 15 秒预算的性能验收。测试过程中会对假服务断言「默认配置下不发生任何写操作」，并断言「原始凭据不出现在发往模型的请求里」。

## ⚠️ 免责声明

1. 本工具仅用于**合法授权的网络安全测试**（如企业内部安全审计、经客户授权的渗透测试），严禁用于未授权的攻击行为。
2. 使用本工具前，必须获得目标存储桶的**书面授权**，否则使用者需自行承担全部法律责任。
3. 启用 `allow_intrusive_write` 会向目标桶写入并删除测试对象，请确认授权范围覆盖此行为。
4. 作者（sjdalu）不对使用本工具产生的任何后果负责，包括但不限于数据泄露、服务中断、法律纠纷等。
5. 请勿将本工具用于违反《网络安全法》《数据安全法》及相关法律法规的场景。

## 📞 作者信息

- 作者：sjdalu
- 项目地址：[https://github.com/bitboy-sys/OSS_scanner](https://github.com/bitboy-sys/OSS_scanner)
- 版本：v2.2.0

## 📝 版本更新日志

| 版本   | 更新时间   | 主要更新内容                                                 |
| ------ | ---------- | ------------------------------------------------------------ |
| v2.2.0 | 2026-10    | 新增临时凭证（STS）认证态扫描：AWS/华为/GCP SigV4（经官方测试向量校验）、阿里云 V1、腾讯云签名；新增 ACL 授权项、版本控制历史恢复、静态网站、防盗链、跨账号复制检测；区域自动发现；每条漏洞生成可运行 PoC 命令（认证态用占位符）；AI 支持 8 家厂商预设（含 DeepSeek）并从环境变量读密钥 |
| v2.1.0 | 2026-10    | 新增 AI 研判能力：执行摘要与修复计划、误报降噪、泄露内容凭据识别与脱敏；提示词可编辑；默认走本地 Ollama，非本机端点需显式确认 |
| v2.0.0 | 2026-10    | 修复严重度误判与 JSON 输出崩溃；引入写操作总闸门（默认关闭）；风险项改为稳定 ID + 元数据表；厂商逻辑声明式重构（新增 GCP / Azure）；端点解析统一；全局令牌桶限速 + 连接池复用，单桶耗时从 100 秒以上降至 15 秒以内；补齐证据字段；HTML 报告开启 autoescape；新增离线测试、LICENSE、.gitignore |
| v1.1   | 2025-10-13 | 新增 hostid-url 自动识别、HTML 报告、日志转存/加密配置检测等 |
| v1.0.1 | 2025-10-09 | 新增 ASCII 启动 Logo、优化 HTML 报告样式、修复配置文件注释读取 bug |
| v1.0.0 | 2025-10-08 | 初始版本，支持 4 大厂商、漏洞检测、多格式报告、多线程扫描   |

## 🔭 后续计划

- **端点族补全**：`s3-accelerate`、`s3.dualstack.{region}`、`oss-{region}-internal` 等变体（区域发现已落地）。
- **域名接管检测**：悬空 CNAME 指向已释放的存储桶（需要 DNS 解析，将引入 `dnspython` 可选依赖）。
- **发现能力**：由关键字生成 Bucket 名候选并批量探测，把工具从「验证器」扩展为「发现 + 验证」。
- **目标定制化路径字典**：由桶名与框架指纹生成针对性敏感路径。
- **输出与集成**：SARIF / CSV 输出、基线对比（本次新增/已修复/仍存在）、Docker 镜像与 CI。
