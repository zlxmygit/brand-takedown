# brand-takedown

brand-takedown 是一个品牌维权 Skill，用于采集网站证据、生成投诉材料和跟进案件进度。

你可以按品牌管理权利资料，把目标网址、证据、投诉通道和回执归到同一案件。Agent 调用 Python 脚本完成取证和材料整理，你审核后提交，再记录处理结果。

## 功能

| 功能 | 用途 |
| --- | --- |
| 品牌档案 | 保存主体、联系人、官方域名、授权经销商和知识产权资料 |
| 网站取证 | 采集页面、网络信息和注册资料，每次生成独立快照与文件校验清单 |
| 投诉材料 | 按版权、商标、外观设计或欺诈等类型整理主张、证据和附件 |
| 案件跟进 | 记录工单、补件、反通知和待办，检查目标网址的访问状态 |
| 域名发现 | 查询证书透明度日志，保留待核实的域名线索 |

## 安装

需要 Python 3.11 或更高版本，以及 Linux 或 macOS。脚本只使用 Python 标准库。

```bash
git clone https://github.com/zlxmygit/brand-takedown.git
cd brand-takedown
python3 scripts/doctor.py
```

诊断结果中的 `ok` 为 `true`，表示本机环境满足运行要求。也可以从 [发布页](https://github.com/zlxmygit/brand-takedown/releases) 下载 ZIP，解压后运行同一命令。

将整个 `brand-takedown/` 目录放入 Agent 的 Skill 目录，保持内部文件结构。具体位置取决于所用 Agent，工具接入方式见 [Agent 接入](references/host-contract.md)。

## 快速上手

下面的命令在仓库根目录运行。`.example` 域名用于展示格式，取证时请换成待核实的网址。

### 1. 建立品牌档案

将示例复制到仓库外，填写品牌主体、联系人、官方域名和权利资料。

```bash
mkdir -p "$HOME/.gemini/brand-protection/example-brand"
cp examples/sample-profile.json "$HOME/.gemini/brand-protection/example-brand/input.json"
export BRAND_TAKEDOWN_REGISTRY="$HOME/.gemini/brand-protection/registry.json"
```

编辑 `input.json` 后，校验并注册档案：

```bash
python3 scripts/brand_registry.py validate \
  --profile-file "$HOME/.gemini/brand-protection/example-brand/input.json"
python3 scripts/brand_registry.py init --slug example-brand \
  --data-dir "$HOME/.gemini/brand-protection/example-brand" \
  --profile-file "$HOME/.gemini/brand-protection/example-brand/input.json"
```

`brand_slug` 与 `--slug` 使用同一个值。证书建议填写绝对路径；相对路径按 `--data-dir` 解析。每个品牌使用独立的本机目录，档案、证据和邮件都保存在仓库外。并发写入依赖本机文件锁，因此数据目录应使用本地磁盘，而非 NFS 或同步云盘。

### 2. 建案并取证

```bash
python3 scripts/case_manager.py create --slug example-brand \
  --url "https://suspect.example/product" --types COPYRIGHT_CLONE
```

命令返回 JSON。把其中的 `case_dir` 填入下方变量：

```bash
export CASE_DIR="上一步返回的案件目录"
python3 scripts/recon_target.py run --slug example-brand \
  --case-dir "$CASE_DIR" --url "https://suspect.example/product"
```

每次取证都会生成一个 `CAP-*` 快照目录，保留页面原始字节和采集信息。网络请求失败时，命令返回非零退出码，并保存失败原因。

取证报告还会整理域名注册资料，以及最多 2 个公网 IP 的注册资料。ASN 信息缺失时，会补充查询网络运营方线索。

补充截图或其他文件时，使用 `add-evidence`；检查已有快照时，使用 `refresh-manifest`：

```bash
python3 scripts/recon_target.py add-evidence --slug example-brand \
  --case-dir "$CASE_DIR" --url "https://suspect.example/product" \
  --source "$HOME/evidence/screenshot.png"
python3 scripts/recon_target.py refresh-manifest \
  --slug example-brand --case-dir "$CASE_DIR"
```

`refresh-manifest` 比对原始清单，文件发生变化时会报错。补充材料会另建快照，原快照保持不变。

### 3. 整理投诉材料

先从服务商官网核对投诉入口，再登记通道。以下名称和邮箱需要替换为核实后的信息：

```bash
python3 scripts/case_manager.py add-channel --slug example-brand \
  --case-dir "$CASE_DIR" --channel-id host \
  --channel-class ENFORCEMENT_SLA --category hosting \
  --provider "服务商名称" --endpoint "abuse@provider.example"
```

将投诉主张写入请求 JSON。每项主张对应一个目标网址，并引用案件中的证据文件。选择通道时可查阅 [投诉通道](references/channel-playbook.md) 和 [法域与权利类型](references/legal-jurisdictions.md)。

<details>
<summary>请求 JSON 字段</summary>

| 字段 | 内容 |
| --- | --- |
| `channel_id`、`subject` | 通道标识和邮件主题 |
| `route`、`jurisdiction` | 投诉类型和适用地区 |
| `provider_role`、`scope_reason` | 服务商角色及适用理由 |
| `endpoint_source_url` | 服务商官方投诉入口的 HTTPS 来源页 |
| `endpoint_verified_by`、`endpoint_verified_at` | 联系方式的核验人和核验时间 |
| `rights_verified_by`、`rights_verified_at` | 权利资料的核验人和核验时间 |
| `authorization_fair_use_review` | 授权、转售及合理使用等情况的审核记录 |
| `claims` | 主张数组，每项填写下述字段 |

每项主张包含 `kind`、`target_url`、`statement`、`legal_basis`、`comparison_or_observed_facts` 和 `evidence`。证据引用格式为 `{"capture_id": "快照标识", "filename": "raw.bin"}`。

知识产权主张还需填写 `right_index`，对应品牌档案中权利数组的下标，从 `0` 开始。产品安全主张需填写 `specific_requirement_and_defect`，说明具体要求和观察到的缺陷。

`route` 支持 `COPYRIGHT_NOTICE`、`TRADEMARK_NOTICE`、`DESIGN_NOTICE`、`ABUSE_REPORT`、`DSA_NOTICE`、`SAFETY_REFERRAL` 和 `REGULATORY_FILING`。当前版权通知模板适用于美国；DSA 通知要求地区为 `EU`，服务商角色为 `hosting`。

核验时间使用带时区的 ISO 8601 格式，并保持在最近 30 天内。请求结构示例见 [`tests/common.py`](tests/common.py)，其中的测试数据仅供了解字段格式。

</details>

设置请求文件路径并生成材料：

```bash
export REQUEST_JSON="$HOME/.gemini/brand-protection/example-brand/request.json"
python3 scripts/packets.py --slug example-brand --case-dir "$CASE_DIR" \
  prepare --request-file "$REQUEST_JSON"
```

### 4. 审核、发送并记录回执

生成结果包含材料目录、`packet_id` 和 `packet_sha256`。检查目录中的 `notice.txt`、收件目标和附件后，将这两个值分别填入 `PACKET_ID` 和 `PACKET_SHA256`。

用户确认这份材料后，记录审批并生成 EML 邮件草稿：

```bash
python3 scripts/packets.py --slug example-brand --case-dir "$CASE_DIR" approve \
  --packet-id "$PACKET_ID" --reviewer "审核人姓名" \
  --reviewed-digest "$PACKET_SHA256" --confirm-human-review
python3 scripts/build_eml.py --slug example-brand --case-dir "$CASE_DIR" \
  --packet-id "$PACKET_ID"
```

在邮箱客户端打开草稿，使用已配置的企业邮箱发送。材料、收件目标或品牌资料变更后，重新生成并审核；审批记录超过 7 天也需重审。

发送后，将回执编号填入 `ACTUAL_RECEIPT`，实际发送时间填入 `ACTUAL_SENT_AT`。时间应包含时区。

```bash
python3 scripts/case_manager.py submit --slug example-brand \
  --case-dir "$CASE_DIR" --channel-id host --packet-id "$PACKET_ID" \
  --submission-ref "$ACTUAL_RECEIPT" --sent-at "$ACTUAL_SENT_AT"
```

### 5. 跟进案件

```bash
python3 scripts/check_liveness.py patrol --slug example-brand
python3 scripts/case_manager.py due --slug example-brand
python3 scripts/ct_radar.py --slug example-brand
```

这三个命令分别检查网址、列出待办和查询域名线索。待办包括催办、补件、升级复核和反通知处理。域名线索会保留到审核人分类处理。

巡检命令可附加 `--check-rdap`，同时查询域名注册状态。结果中的 `clienthold` 和 `serverhold` 可用于核对域名是否被暂停解析。

使用 `update-channel` 更新工单，用 `escalate` 准备下一轮跟进。收到反通知后，使用 `counter-notice` 保存来源邮件和收件时间，再按 [反通知处理](references/escalation-and-counter-notice.md) 核对后续事项。各命令的参数可通过 `--help` 查看。

## 迁移已有案件

当前案件格式为 schema 2。迁移时先备份原目录和注册表，再使用新的私有目录建档、建案。通过 `add-evidence` 导入历史材料，保留原始来源、取证时间和邮件回执。未处理的反通知需要一并录入待办。

## 开发与测试

```bash
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -v
python3 scripts/package_skill.py --out /tmp/brand-takedown.zip
```

测试覆盖案件隔离、并发写入、网络访问、证据校验、审批和命令行流程。打包器按文件清单收录源码和文档，并生成 `SHA256SUMS.txt`。

开发说明见 [贡献指南](CONTRIBUTING.md)，数据存储要求见 [安全说明](SECURITY.md)。
