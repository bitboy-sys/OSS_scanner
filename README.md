# OSS_Scanner

![img](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%27400%27%20height=%27256%27/%3e)![image](https://img.shields.io/badge/Python-3.7%2B-blue)

![img](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%27400%27%20height=%27256%27/%3e)![image](https://img.shields.io/badge/License-MIT-green)

![img](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%27400%27%20height=%27256%27/%3e)![image](https://img.shields.io/badge/Author-sjdalu-orange)

OSS_Scanner 是一款**多厂商 OSS 存储桶漏洞扫描工具**，支持阿里云、腾讯云、华为云、AWS S3 等主流对象存储服务，可检测敏感文件泄露、匿名上传 / 删除、CORS 配置过宽等 10 + 类安全风险，帮助安全测试人员快速发现存储桶配置漏洞。

## 📋 功能特性

| 功能模块       | 检测能力                                                     |
| -------------- | ------------------------------------------------------------ |
| 敏感文件扫描   | 密钥文件（.env、id_rsa）、数据库备份（.sql、.bak）、配置文件（wp-config.php）等 |
| 权限漏洞检测   | 公开可列目录、匿名 PUT 上传、匿名 POST 表单上传、匿名 DELETE 权限 |
| 配置风险检测   | CORS 配置过宽（允许任意域名跨域）、敏感 HTTP 头泄露（X-OSS-Meta-*） |
| 日志与版本风险 | 访问日志泄露（/logs/、/accesslog/）、版本控制文件泄露（S3/OSS 特有） |
| 路径穿越检测   | 目录遍历漏洞（../../etc/passwd 等敏感路径访问）              |
| 报告生成       | 支持 Text/JSON/HTML 三种输出格式，HTML 报告可视化展示风险等级 |
| 多线程扫描     | 可配置扫描线程数，提升批量 Bucket 检测效率                   |
| 兼容性         | 支持 Windows/macOS/Linux，自动适配不同厂商存储桶 URL 格式    |

## 🛠️ 安装步骤

### 1. 克隆项目

```bash
git clone https://github.com/你的GitHub用户名/OSS_Scanner.git
cd OSS_Scanner
```

### 2. 安装依赖

工具依赖 Python 3.7+，使用 pip 安装所需包：

```bash
pip install -r requirements.txt
```

### 3. 依赖说明

`requirements.txt` 内容如下：



```txt
requests>=2.31.0
colorama>=0.4.6
tqdm>=4.66.1
configparser>=5.3.0
```

## 🚀 快速使用

### 基础命令（扫描阿里云 Bucket）

```bash
# 扫描阿里云Bucket，生成HTML报告
python main.py \
  --cloud aliyun \
  --region ap-southeast-1 \
  --bucket 你的测试Bucket名称 \
  --output html \
  --output-file ./reports/aliyun_scan.html \
  --progress
```

```bash
# 输入阿里云hostid-url，自动识别bucket和region，并生成HTML报告
python main.py --cloud aliyun --hostid-url http://bucket.oss-region.aliyuns.com --output html --output-file ./reports/aliyun_scan.html
```



### 批量扫描（从文件读取 Bucket 列表）

```bash
# 从bucket_list.txt读取Bucket，多线程扫描（10线程）
python main.py \
  --cloud tencent \
  --region ap-guangzhou \
  --bucket-file ./bucket_list.txt \
  --thread 10 \
  --output json \
  --output-file ./reports/tencent_batch_scan.json
```

### 关键参数说明

| 参数            | 作用                        | 必填   | 示例                                             |
| --------------- | --------------------------- | ------ | ------------------------------------------------ |
| `--cloud`       | 目标云厂商                  | 是     | `aliyun`/`tencent`/`huawei`/`aws`                |
| `--region`      | 存储桶区域（注意格式）      | 是     | 阿里云：`ap-southeast-1`；腾讯云：`ap-guangzhou` |
| `--bucket`      | 单个 Bucket 名称            | 二选一 | `my-test-bucket`                                 |
| `--bucket-list` | 多个 Bucket（逗号分隔）     | 二选一 | `b1,b2,b3`                                       |
| `--bucket-file` | Bucket 列表文件（每行一个） | 二选一 | `./bucket_list.txt`                              |
| `--output`      | 输出格式                    | 否     | `text`（默认）/`json`/`html`                     |
| `--output-file` | 结果保存路径                | 否     | `./scan_report.html`                             |
| `--thread`      | 扫描线程数                  | 否     | `5`（默认）/`10`                                 |
| `--progress`    | 显示扫描进度条              | 否     | 无需值，添加参数即可                             |
| `--proxy`       | 代理地址（如 HTTP 代理）    | 否     | `http://127.0.0.1:8080`                          |

## ⚙️ 配置文件说明

核心配置文件为 `config/config.ini`，可根据需求调整开关和参数：

```ini
[DEFAULT]
# 基础配置
request_timeout = 10          # 请求超时时间（秒）
request_interval = 1          # 请求间隔（秒，避免触发防护）
max_retry = 2                 # 请求失败重试次数
https_only = false            # 是否仅使用HTTPS请求

# 漏洞检测开关（true=开启，false=关闭）
scan_put_upload = true        # 检测匿名PUT上传
scan_post_upload = true       # 检测匿名POST上传
scan_delete_perm = true       # 检测匿名DELETE权限
scan_cors = true              # 检测CORS配置过宽
scan_logs = true              # 检测访问日志泄露
scan_directory_traversal = true  # 检测目录遍历
scan_sensitive_headers = true    # 检测敏感HTTP头

[CLOUD_TEMPLATES]
# 各厂商存储桶URL模板（无需修改）
aliyun_http = http://{bucket}.oss-{region}.aliyuncs.com
tencent_http = http://{bucket}.cos.{region}.myqcloud.com
```

## 📊 漏洞检测范围

| 漏洞类型         | 风险等级 | 检测逻辑                                                     |
| ---------------- | -------- | ------------------------------------------------------------ |
| 敏感密钥文件泄露 | 严重     | 扫描 `.env`/`id_rsa`/`access_key.txt` 等路径，判断是否可匿名访问 |
| 数据库备份泄露   | 严重     | 检测 `backup/*.sql`/`db.bak` 等备份文件，判断是否可下载      |
| 匿名 PUT 上传    | 严重     | 尝试上传随机测试文件，返回 200/201 则判定漏洞存在（上传后自动清理） |
| 匿名 DELETE 权限 | 严重     | 先上传测试文件，再尝试删除，返回 200/204 则判定漏洞存在      |
| 公开可列目录     | 高危     | 访问 Bucket 根目录，判断是否返回 XML 格式的文件列表          |
| 访问日志泄露     | 高危     | 检测 `/logs/`/`/accesslog/` 等常见日志路径，判断是否可访问   |
| CORS 配置过宽    | 中危     | 发送 OPTIONS 请求，判断是否允许 `Origin: *` 且支持 PUT/POST 方法 |
| 目录遍历         | 中危     | 尝试访问 `../../etc/passwd` 等路径，判断是否返回敏感文件内容 |
| 敏感 HTTP 头泄露 | 低危     | 检查响应头是否包含 `X-OSS-Meta-*`/`X-Amz-Storage-Class` 等敏感信息 |

## ⚠️ 免责声明

1. 本工具仅用于**合法授权的网络安全测试**（如企业内部安全审计、经客户授权的渗透测试），严禁用于未授权的攻击行为。
2. 使用本工具前，必须获得目标存储桶的**书面授权**，否则使用者需自行承担全部法律责任。
3. 作者（sjdalu）不对使用本工具产生的任何后果负责，包括但不限于数据泄露、服务中断、法律纠纷等。
4. 请勿将本工具用于违反《网络安全法》《数据安全法》及相关法律法规的场景。

## 📞 作者信息

- 作者：sjdalu
- 项目地址：[https://github.com/ 你的 GitHub 用户名 / OSS_Scanner](https://github.com/你的GitHub用户名/OSS_Scanner)
- 版本：v1.1（2025-10）

## 📝 版本更新日志

| 版本   | 更新时间   | 主要更新内容                                                 |
| ------ | ---------- | ------------------------------------------------------------ |
| v1.1   | 2025.10.13 | 新增 hostid-url 自动识别、炫酷 HTML 报告、日志转存/加密配置检测等 5+ 漏洞类型 |
| v1.0.1 | 2025-10-09 | 新增 ASCII 启动 Logo、优化 HTML 报告样式、修复配置文件注释读取 bug |
| v1.0.0 | 2025-10-08 | 初始版本，支持 4 大厂商、10 + 漏洞检测、多格式报告生成、多线程扫描 |
