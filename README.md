# brand-takedown

**面向真实业务场景的人工监督（Human-Supervised）品牌维权、取证与投诉草稿生成 Skill。**

`brand-takedown` 帮助品牌方按品牌与案件隔离管理权利资料、采集带完整性清单的网页/DNS/RDAP/ASN 证据、初筛视觉雷同盗图、起草受约束的投诉通知（支持 **Lumen Database** 公开归档防隐私暴露切换），并持续跟进工单 SLA、反通知法律待办与仿冒域名线索。

> **核心定位与非目标边界**  
> 本工具**不是**无人值守全自动封站或执法系统：不保证投诉下线结果，也**不自动发送邮件、自动提交网页表单、代理结账买样或主动触发第三方公开存档**（如 Wayback）。所有对外提交动作、权属事实认定及反通知法律应对均必须由人工审核并显式确认后执行。

版本演进见 [更新日志](CHANGELOG.md) 与 [GitHub Releases](https://github.com/zlxmygit/brand-takedown/releases)。

---

## 核心能力总览

| 模块 | 对应脚本 | 核心能力 |
| --- | --- | --- |
| **品牌与权属建档** | `brand_registry.py` | 按 UUID 隔离品牌数据目录与全局注册表；校验商标、外观设计/专利、版权原件清单、官方/授权白名单域名及可选公开归档代理署名 (`public_filing_agent`) |
| **网页取证与存证校验** | `recon_target.py` | 公网 IP Pinning 直连采集原始响应字节；域名 RDAP 父域回退查询 + 最多 2 个公网 IP 的 IANA RDAP / Team Cymru DoH ASN 归属线索；追加式 `CAP-*` 快照与 `SHA-256` + 可选本地 `HMAC-SHA256` 清单校验 |
| **零依赖盗图初筛** | `recon_target.py compare-images` | 纯 Python 标准库解码 8-bit 非隔行 PNG（支持过滤 `0..4`、色彩类型 `0/2/3/4/6`）与未压缩 `8/24/32`-bit BMP（macOS 可回退 `/usr/bin/sips`），输出 64-bit `dHash` 汉明距离作为复核线索 |
| **投诉材料与隐私门控** | `packets.py` / `build_eml.py` | 校验 7 类法律路线与 6 类主张的证据、权属时效与属地匹配；在预期公开归档渠道自动切换至代理署名（`fail-closed`）；人工哈希绑定审批后生成 `X-Unsent: 1` `.eml` 草稿 |
| **案件生命周期与巡检** | `case_manager.py` / `check_liveness.py` | 管控案件状态流转、多通道 SLA 倒计时、Tier-2/Tier-3 升级规划、反通知独立法律待办、以及多 URL 存活探测与 RDAP 注册冻结 (`clienthold` / `serverhold`) 信号查询 |
| **域名雷达与仿冒快筛** | `ct_radar.py` | 查询证书透明度 (CT) 日志，并支持离线生成拼写抢注、连字符、ASCII 同形混淆及商业组合词变体，通过受控 HTTPS DoH 查询 `A` / `MX` 存活记录后交由人工队列分诊 |

---

## 安全与工程边界

| 维度 | 约束机制 |
| --- | --- |
| **零第三方运行依赖** | 仅使用 Python **3.11+** 标准库；不依赖外部 `curl`、`dig`、`whois`、`openssl`，代码库静态禁用 `shell=True` 与内置发件密码 |
| **防 SSRF 与出站受控** | 每次重定向重新解析并校验全公网 IP，连接阶段 IP Pinning 绑定目标地址、校验证书与主机名并限制响应体积与超时；代理抓取、`Referer` 伪造与自动 Wayback 已禁用 |
| **原子存储与隔离** | 目录仅在本机私有 POSIX 文件系统运行（权限 `0700` / `0600`），采用文件锁、临时文件 `fsync`、原子替换与乐观 `revision` 并发冲突拦截，严禁跨品牌复用案件目录 |
| **防提示注入与边界诚实** | 所有抓取网页、RDAP、IP/ASN 线索及 `dHash` 结果强制标记 `trusted_as_instructions: false`；明确标注线索属性（如 `HOSTING_HINT_NOT_PROOF_OF_ATTRIBUTION`、`VISUAL_SIMILARITY_HINT_NOT_PROOF_OF_INFRINGEMENT`），不作为法律实锤 |
| **完整性与审批边界** | 本地 `SHA-256`、`HMAC-SHA256`（依赖 `BRAND_TAKEDOWN_HMAC_KEY`）与审批记录均用于本地防误改/流转留痕，**不等同于**第三方可信时间戳机构（TSA）、司法公证或授权身份数字签名 |

---

## 环境要求、安装与 Agent 接入

- **运行环境**：Python **3.11+**，Linux 或 macOS，**本机私有 POSIX 文件系统**（因依赖本地文件锁，请勿将运行数据目录放在 NFS、SMB 或双向同步云盘上）。
- **克隆并诊断环境**：

```bash
git clone https://github.com/zlxmygit/brand-takedown.git
cd brand-takedown
python3 scripts/doctor.py
```

`doctor.py` 输出 JSON 且 `"ok": true` 时表示本机基础环境通过。其中的 `capabilities` 字段会如实声明当前内置状态（例如 `direct_http: true`、`rdap: true`、`ct_radar: true`、`approval_bound_eml: true`；而 `gmail_send`、`gmail_sync`、`browser_checkout`、`proxy`、`public_archival`、`scheduler` 默认为 `false`）。

> 也可以从 [GitHub Releases](https://github.com/zlxmygit/brand-takedown/releases) 下载对应版本源码包，解压后运行同一命令验证。

### Skill 挂载与宿主工具协作

将整个 `brand-takedown/` 目录放入你的 AI Agent 所支持的 Skill 目录（保持内部目录与文件完整）。本 Skill 刻意将核心逻辑与具体宿主解耦，不假定固定工具名或内置凭证；外部协作分工如下：

- **企业邮箱 / Gmail Send-As 协作**：Skill 仅产出带 `X-Unsent: 1` 头的 `.eml` 草稿，发件账户认证、SPF/DKIM 校验及实际发送由宿主的 Gmail 插件（企业邮箱转发并完成 `Send-As` 别名验证）或用户本地邮箱客户端执行；发送后将真实回执写回案件，收到的服务商回复或反通知再录入后续待办。
- **浏览器辅助取证 / 定时巡检**：动态渲染页面的交互截图与登录验证码由宿主的浏览器工作流人工介入完成，文件通过 `add-evidence` 导入；定期巡检由宿主调度器触发巡检命令，但投诉提交仍须人工确认。详细接口见 [宿主能力契约](references/host-contract.md)。

---

## 全流程使用指南

> 以下命令默认在仓库根目录执行，并统一以 `.example` 占位域演示格式；真实维权时请务必替换为核实后的域名与私有目录路径。**所有品牌档案、权属证书、案件记录、证据和邮件必须存储在仓库目录之外**（`.gitignore` 只是辅助，切勿把真实数据放入仓库或提交到 Git）。

### 1. 建立品牌档案

先设置私有注册表位置（也可在任意子命令前通过 `--registry <path>` 指定），再从模板复制配置文件到仓库外的私有目录并填写真实主体、联系人、官方域名及权利资料：

```bash
mkdir -p "$HOME/.gemini/brand-protection/example-brand"
cp examples/sample-profile.json "$HOME/.gemini/brand-protection/example-brand/input.json"
export BRAND_TAKEDOWN_REGISTRY="$HOME/.gemini/brand-protection/registry.json"
```

关键字段提示：
- `brand_slug` 必须与建档参数 `--slug` 完全一致；
- `target_markets` 支持 `US`、`CA`、`EU`、`UK`、`AU`、`CN_EXPORT`、`GLOBAL`；
- 权利证书 `cert_file_path` 建议使用绝对路径（若填写相对路径，建档时按 `--data-dir` 解析并校验文件可读）；
- **公开归档代理（可选，`v1.2.0+`）**：如果后续需要向会公开归档投诉文本的服务商或 **Lumen Database** 递交投诉，建议在品牌档案配置可选对象 `public_filing_agent`（包含 `name`、`title`、`legal_email`、`entity_address`，可选 `phone`），避免经办人个人姓名、直连邮箱或办公地址被公开索引。

校验并注册档案：

```bash
python3 scripts/brand_registry.py validate \
  --profile-file "$HOME/.gemini/brand-protection/example-brand/input.json"
python3 scripts/brand_registry.py init --slug example-brand \
  --data-dir "$HOME/.gemini/brand-protection/example-brand" \
  --profile-file "$HOME/.gemini/brand-protection/example-brand/input.json"
```

可使用 `brand_registry.py list` 查看已注册品牌，或用 `brand_registry.py check-allowlist --slug example-brand --url "<target-url>"` 验证目标 URL 是否落入官方域名/白名单保护范围（官方及授权域名会自动 `fail-closed` 拒绝建案）。

### 2. 建案、安全取证与完整性校验

创建案件并录入侵权类型（`COPYRIGHT_CLONE`、`TRADEMARK_IMPERSONATION`、`COUNTERFEIT_GOODS`、`DESIGN_PATENT_COPY`、`PHISHING_OR_FAKE_TRACKING` 支持多项空格分隔）：

```bash
python3 scripts/case_manager.py create --slug example-brand \
  --url "https://suspect.example/product" --types COPYRIGHT_CLONE
```

命令会返回包含 `case_dir` 的 JSON；将返回的真实目录路径写入变量后执行网页与基础网络取证：

```bash
export CASE_DIR="上一步返回的实际 case_dir 路径"
python3 scripts/recon_target.py run --slug example-brand \
  --case-dir "$CASE_DIR" --url "https://suspect.example/product"
```

取证行为说明：
- 每次执行创建独立只读语义目录 `evidence/CAP-*`，保存页面原始字节 (`raw.bin`)、响应头、DNS 结果与 `evidence-manifest.json`；若网络抓取失败，返回非零退出码并保留 `FAILED`/`PARTIAL` 失败报告，**严禁将失败快照用作投诉证据**。
- `recon-report.json` 自动记录域名 RDAP（支持子域名逐级回退至含常见二级公共后缀的可注册主域）以及针对解析结果的最多 **2 个公网 IP** 归属线索（IANA IPv4/IPv6 RDAP 与 Google DoH Team Cymru TXT ASN 查询），该字段标记为 `HOSTING_HINT_NOT_PROOF_OF_ATTRIBUTION`。
- 补充人工浏览器截图、律师函 PDF 等本地材料时，**必须新建快照**而非修改旧快照：

```bash
python3 scripts/recon_target.py add-evidence --slug example-brand \
  --case-dir "$CASE_DIR" --url "https://suspect.example/product" \
  --source "$HOME/evidence/screenshot.png"
python3 scripts/recon_target.py refresh-manifest \
  --slug example-brand --case-dir "$CASE_DIR"
```

`refresh-manifest` 仅做只读校验，一旦文件增删改或清单摘要与 `case.json` 记录不符即报错，绝不重新覆盖旧哈希。

#### 可选增强：本地 HMAC-SHA256 签名与 dHash 盗图初筛 (`v1.4.0+`)

- **本地防篡改 HMAC 校验**：若在抓取或 `add-evidence` 前设置环境变量 `BRAND_TAKEDOWN_HMAC_KEY`，新生成的 `evidence-manifest.json` 会附加 `hmac_algorithm: "HMAC-SHA256"` 与 `hmac_sha256` 字段；后续校验传入 `--require-hmac` 可强制拒绝未签名、缺密钥或密钥不匹配的快照：

```bash
BRAND_TAKEDOWN_HMAC_KEY="replace-with-local-secret" python3 scripts/recon_target.py refresh-manifest \
  --slug example-brand --case-dir "$CASE_DIR" --require-hmac
```

- **零依赖 64-bit `dHash` 视觉比对**：可离线计算正品原图与嫌疑页面截图的差异感知哈希汉明距离（默认阈值 `--threshold 10`）：

```bash
python3 scripts/recon_target.py compare-images --slug example-brand --case-dir "$CASE_DIR" \
  --original "$HOME/brand/original.png" --suspect "$HOME/evidence/suspect.png" --threshold 10
```

> **图像解码边界**：纯标准库原生支持 **8-bit 非隔行 PNG** 与 **未压缩 `8/24/32`-bit BMP**；在 **macOS** 上如传入 JPEG/WebP 等其他常见格式，会自动回退调用系统 `/usr/bin/sips` 转为临时 PNG 解析，但在无 `sips` 的 Linux 上需先自行转换为 PNG 或 BMP。输出字段 `"use": "VISUAL_SIMILARITY_HINT_NOT_PROOF_OF_INFRINGEMENT"` 仅作视觉相似初筛线索，不构成侵权法律结论。

### 3. 登记投诉通道与整理结构化材料

先从服务商官方网站 HTTPS 页面独立核实投诉入口（**禁止仅凭目标侵权网站自身展示的联系方式发函**），再向案件登记通道：

```bash
python3 scripts/case_manager.py add-channel --slug example-brand \
  --case-dir "$CASE_DIR" --channel-id host \
  --channel-class ENFORCEMENT_SLA --category hosting \
  --provider "服务商官方名称" --endpoint "abuse@provider.example"
```

- `--channel-class` 可选：`ENFORCEMENT_SLA`（按服务商类型计算商业 SLA 跟进时限，如 `payment`/`saas`/`phishing` 默认 48 小时，`registrar`/`hosting`/`cdn`/`esp` 默认 72 小时，`search_ads` 默认 120 小时）或 `REGULATORY_FILING`（监管/行政通报，仅接受 `REGULATORY_FILING` 或 `SAFETY_REFERRAL` 路线，不计商业催办 SLA）。

接下来撰写投诉请求 JSON 并调用 `packets.py prepare` 生成审校数据包。选择法律路线、属地与模板措辞前请对照查阅 [投诉通道手册](references/channel-playbook.md) 与 [法域与权利类型](references/legal-jurisdictions.md)。

<details>
<summary>请求 JSON 完整字段、路由校验规则与最小示例（展开查看）</summary>

| 字段 | 说明与硬校验要求 |
| --- | --- |
| `channel_id`、`subject` | 目标通道 ID 与邮件主题（严格拦截 `\r`/`\n` 邮件头注入） |
| `route`、`jurisdiction` | 投诉路线与法定适用辖区（必须在品牌 `target_markets` 中） |
| `provider_role`、`scope_reason` | 服务商法律角色（如 `hosting`、`registrar`、`cdn`、`payment`、`saas`）及适用理由 |
| `endpoint_source_url` | 独立核验的服务商官方 HTTPS 页面 URL（禁止指向涉案侵权域或关联跳转域） |
| `endpoint_verified_by`、`endpoint_verified_at` | 联系方式核验人及带时区的 ISO 8601 时间（须在最近 **30 天** 内） |
| `rights_verified_by`、`rights_verified_at` | 权利证明核验人及带时区的 ISO 8601 时间（须在最近 **30 天** 内） |
| `authorization_fair_use_review` | 关于经销授权、转售及合理使用排除情况的复核记录 |
| `public_archive_expected` | 可选布尔值；若通道会转告涉案方或进入 **Lumen Database** 公开归档库应设为 `true`，此时系统强制使用 `public_filing_agent`（若未配置且未传 `allow_primary_signatory_in_public_archive: true`，直接 `fail-closed` 拒绝出单） |
| `use_public_filing_agent` | 可选布尔值；显式要求改用品牌档案中配置的 `public_filing_agent` 署名 |
| `allow_primary_signatory_in_public_archive` | 可选布尔值；仅当经隐私审核明确允许在公开归档中披露主签署人时显式设为 `true` |
| `claims` | 主张数组（每项需包含 `kind`、`target_url`、`statement`、`legal_basis`、`comparison_or_observed_facts`、`evidence`；引用已抓取有效的 `capture_id` 与非元数据实体文件） |

**合法 `route` 与允许的 `claim.kind` 及属地限制（与 `scripts/packets.py` 严格一致）**：
- `COPYRIGHT_NOTICE` -> `COPYRIGHT`（现行模板仅支持 `jurisdiction == "US"` 的 DMCA 通知）
- `TRADEMARK_NOTICE` -> `TRADEMARK` / `COUNTERFEIT`
- `DESIGN_NOTICE` -> `DESIGN`
- `ABUSE_REPORT` -> `PHISHING`
- `DSA_NOTICE` -> 支持所有 6 类 `kind`（强制要求 `jurisdiction == "EU"` 且 `provider_role == "hosting"`）
- `SAFETY_REFERRAL` -> `PRODUCT_SAFETY`（需填写 `specific_requirement_and_defect`）
- `REGULATORY_FILING` -> 支持所有 6 类 `kind`（唯一或与 `ABUSE_REPORT` 一并支持 `GLOBAL`/`CN_EXPORT` 市场的纯通报路径）

> 知识产权主张还需填写从 `0` 开始的 `right_index`（对应品牌档案对应资产数组下标）；非版权类已注册商标/外观专利主张会自动校验未过期、属地一致且附带实体证书 `cert_file_path`。完整示例结构可参见 [`tests/common.py`](tests/common.py)，示例模板参见 [`templates/`](templates/notices-registrar-hosting-cdn.md)。

```json
{
  "channel_id": "host",
  "route": "COPYRIGHT_NOTICE",
  "jurisdiction": "US",
  "subject": "Request to review copied original material",
  "provider_role": "hosting",
  "scope_reason": "US copyright claim at a hosting provider accepting DMCA notices",
  "endpoint_source_url": "https://provider.example/legal/dmca",
  "endpoint_verified_by": "Reviewer Name",
  "endpoint_verified_at": "2026-11-13T02:00:00Z",
  "rights_verified_by": "Reviewer Name",
  "rights_verified_at": "2026-11-13T02:00:00Z",
  "authorization_fair_use_review": "Verified no license, authorized reseller match, or fair use",
  "public_archive_expected": false,
  "claims": [
    {
      "kind": "COPYRIGHT",
      "target_url": "https://suspect.example/product",
      "right_index": 0,
      "statement": "Product photography copied from original work",
      "legal_basis": "17 U.S.C. 512(c)(3)",
      "comparison_or_observed_facts": "Side-by-side match with original asset and CAP evidence",
      "evidence": [
        { "capture_id": "CAP-...", "filename": "raw.bin" }
      ]
    }
  ]
}
```

</details>

生成受审校投诉包（总附件体积上限 15 MiB）：

```bash
export REQUEST_JSON="$HOME/.gemini/brand-protection/example-brand/request.json"
python3 scripts/packets.py --slug example-brand --case-dir "$CASE_DIR" \
  prepare --request-file "$REQUEST_JSON"
```

### 4. 人工复核审批、生成 EML 草稿与登记回执

上一条命令会返回包含 `packet_id`、`packet_sha256` 与 `packet_dir` 的 JSON。请打开审阅 `notice.txt` 正文、收件人邮箱、署名身份和附件清单，确认无误后执行哈希绑定审批并导出草稿：

```bash
export PACKET_ID="上一步返回的 PKT-... 值"
export PACKET_SHA256="上一步返回的 packet_sha256 值"

python3 scripts/packets.py --slug example-brand --case-dir "$CASE_DIR" approve \
  --packet-id "$PACKET_ID" --reviewer "实际审批人姓名" \
  --reviewed-digest "$PACKET_SHA256" --confirm-human-review

python3 scripts/build_eml.py --slug example-brand --case-dir "$CASE_DIR" \
  --packet-id "$PACKET_ID"
```

注意事项：
- 若正文、附件、收件目标或品牌主体资料发生变化，审批立即失效；审批记录超过 **7 天** 亦需重审（可通过 `packets.py --slug ... --case-dir ... verify --packet-id "$PACKET_ID"` 检查有效性）。
- `build_eml.py` 仅写出带 `X-Unsent: 1` 的本地 `.eml` 文件且返回 `"sent": false`。请使用你已验证的企业邮箱客户端或宿主的 Gmail `Send-As` 企业别名工具人工发出。

**只有在实际完成提交/发送并拿到凭证后**，才能回填提交回执：

```bash
python3 scripts/case_manager.py submit --slug example-brand \
  --case-dir "$CASE_DIR" --channel-id host --packet-id "$PACKET_ID" \
  --submission-ref "$ACTUAL_RECEIPT" --sent-at "$ACTUAL_SENT_AT"
```

> `$ACTUAL_SENT_AT` 需采用带时区的 ISO 8601 格式（例如 `2026-11-13T10:30:00+08:00` 或 `2026-11-13T02:30:00Z`）。

### 5. 巡检存活、工单升级、反通知处置与域名雷达

#### 5.1 存活探测与 RDAP 注册状态检测 (`v1.1.0+`)

```bash
# 全品牌批量巡检所有案件，附带查询按主机去重的 RDAP 注册锁定状态
python3 scripts/check_liveness.py patrol --slug example-brand --check-rdap

# 仅探测单个案件
python3 scripts/check_liveness.py probe --slug example-brand --case-dir "$CASE_DIR" --check-rdap
```

巡检会逐一访问案件下的全部 URL 与关联跳转/隐匿域名，**不会将单页 404、空 DNS 或页面停用声明文字自动认定为整案彻底下线**；附加 `--check-rdap` 时，若返回归一化状态包含 `clienthold` 或 `serverhold`，可用于辅助复核注册商是否已冻结解析。

#### 5.2 待办扫描、状态推进与反通知法律处置

```bash
# 查看全品牌待办（催办/补件/Tier-3人工复核/未决反通知/异常案件）与总览
python3 scripts/case_manager.py due --slug example-brand
python3 scripts/case_manager.py summary --slug example-brand

# 更新通道状态（如 ACKNOWLEDGED / NEED_MORE_INFO / RESOLVED / REJECTED）与工单号
python3 scripts/case_manager.py update-channel --slug example-brand --case-dir "$CASE_DIR" \
  --channel-id host --status NEED_MORE_INFO --ticket-ref "TICKET-12345"

# 登记关联隐匿支付/跳板域名，或计划升级轮次（仅更新状态规划，不自动发信）
python3 scripts/case_manager.py add-cloak --slug example-brand --case-dir "$CASE_DIR" --domain "cloak-pay.example"
python3 scripts/case_manager.py escalate --slug example-brand --case-dir "$CASE_DIR" --channel-id host
```

收到对方提交的反通知（Counter-Notice）时，必须记录来源凭证并由法务/律师评估是否需要在法定窗口内提起司法诉讼或行政措施；处置流程见 [升级与反通知指南](references/escalation-and-counter-notice.md)：

```bash
# 登记反通知（若提供 --provider-received-at，系统仅按周末顺延计算 10-14 工作日非法律参考区间，不可替代律师日历判定）
python3 scripts/case_manager.py counter-notice --slug example-brand --case-dir "$CASE_DIR" \
  --channel-id host --received-at "2026-11-13T03:00:00Z" \
  --summary "收到对方反通知，需律师核查是否起诉" --source-ref "eml-msg-id-or-ticket"

# 律师人工处置完成后关闭法律待办
python3 scripts/case_manager.py resolve-legal --slug example-brand --case-dir "$CASE_DIR" \
  --task-id "$LEGAL_TASK_ID" --reviewer "Counsel Name" \
  --disposition "完成法务复核并记录后续处置决定"
```

#### 5.3 仿冒域名雷达与人工分诊 (`v1.3.0+`)

```bash
# 默认 CT 证书透明度日志雷达扫描
python3 scripts/ct_radar.py --slug example-brand

# 开启离线拼写抢注/连字符/ASCII 同形混淆/商业组合词变体生成 + HTTPS DoH A/MX 存活快筛（限制 1-60 个）
python3 scripts/ct_radar.py --slug example-brand --include-lookalikes --lookalike-limit 20
```

所有新增域名候选都会保留在 `PENDING_REVIEW` 状态（既能捕捉未签发 SSL 证书但已配置仿冒发信 `MX` 记录的钓鱼域，也不会将网络报错掩盖成“无新域名”）。经审核人核实后，必须显式分诊移出待复核队列：

```bash
python3 scripts/ct_radar.py --slug example-brand \
  --triage-domain "lookalike-suspect.example" \
  --decision CONFIRMED_FOR_REVIEWED_CASE \
  --reviewer "Reviewer Name" \
  --rationale "核实页面与品牌高仿并准备建案取证"
```

`--decision` 允许值为：`CONFIRMED_FOR_REVIEWED_CASE`（确认需建案打击）、`REJECTED`（误报/无关站点）、`AUTHORIZED`（确认属已授权合作方）。

---

## 仓库目录与参考文档导航

```text
brand-takedown/
├── SKILL.md                     # Agent 执行主规范（受长度与链接契约检查保护）
├── CHANGELOG.md                 # 各版本变更记录
├── docs/
│   ├── audit-remediation.md     # 39 项安全审计整改映射台账 (BT-01 .. BT-39)
│   ├── source-checksums.json    # 受控源码 SHA-256 完整性清单（CI 强校验）
│   └── releases/                # v1.0.1 ~ v1.4.0 独立版本说明
├── examples/
│   └── sample-profile.json      # 完全脱敏的通用示例档案（严禁直接用于真实投诉）
├── references/                  # 业务与宿主接入专项手册
├── scripts/                     # 纯 Python 3.11+ 标准库运行与打包脚本
├── templates/                   # 档案 Schema 与跨通道投诉文书模板
└── tests/                       # 168 项离线回归、安全边界与 CLI 测试套件
```

### 核心参考资料与模板

| 文档 | 内容摘要 |
| --- | --- |
| [宿主能力契约](references/host-contract.md) | Agent 工具边界、邮件 `Send-As` 分工、浏览器与调度器接入要求、防提示注入规则 |
| [投诉通道手册](references/channel-playbook.md) | 注册商 / 托管商 / CDN / 支付通道 / SaaS / 搜索广告选路策略及 **Lumen Database** 防隐私暴露说明 |
| [法域与权利类型](references/legal-jurisdictions.md) | 美国 DMCA、欧盟 DSA 第 16 条、商标/外观/产品安全分路条件与适用范围 |
| [升级与反通知指南](references/escalation-and-counter-notice.md) | 通道升级节奏、反通知 10–14 工作日估算边界与律师核查清单 |
| [海关备案与产品安全](references/customs-and-safety.md) | 边境执法备案与监管机构安全通报补充指引 |
| [政策依据来源清单](references/policy-sources.json) | 各法域规则与安全机制的出处、适用范围与验证日期索引 |
| [档案 Schema](templates/profile.schema.json) | 严格闭环 JSON Schema（`additionalProperties: false`） |
| [域名/主机/CDN 通知模板](templates/notices-registrar-hosting-cdn.md) | 面向基础设施提供方的结构化投诉模板 |
| [SaaS/支付/钓鱼通知模板](templates/notices-saas-payment-phishing.md) | 面向建站、支付与仿冒欺诈通道的结构化投诉模板 |
| [升级催办与通报模板](templates/notices-escalation-chaser.md) | 多轮催办、升级复核与监管通报模板 |
| [安全审计台账](docs/audit-remediation.md) | `BT-01` 至 `BT-39` 工程防护映射表 |

---

## 兼容性与历史案件迁移

当前案件格式固定为 **`schema_version: 2`**；出于安全与完整性隔离，早期直接修改旧版 `case.json`、未审批导出 EML、任意路径 `--case-dir`、代理参数以及自动归档命令已永久移除。

**请勿尝试就地覆写历史旧目录：**
1. 先对原私有品牌与案件目录执行只读备份；
2. 新建私有状态目录与新注册表，重新初始化品牌档案与 `case_manager.py create` 案件；
3. 历史证据文件请通过 `recon_target.py add-evidence` 作为新快照导入并注明原始出处与取证时间（不要把导入日期冒充为历史原始抓包时间）；
4. 尚未完结的历史邮件回执与反通知需单独核对后重新登记进当前待办队列。

---

## 开发、测试、打包与校验边界

### 本地完整回归与 CI 对齐校验

仓库配置了覆盖 **Linux (`ubuntu-24.04`) 与 macOS (`macos-15`) × Python `3.11` 与 `3.13`** 的自动化流水线（[ci.yml](.github/workflows/ci.yml)）。修改代码或文档后，请在提交前完整运行以下校验（若改动了仓库文件，须同步刷新 [source-checksums.json](docs/source-checksums.json)）：

```bash
# 1. 源码清单 SHA-256 完整性自检
python3 - <<'PY'
import hashlib, json, pathlib
d = json.loads(pathlib.Path("docs/source-checksums.json").read_text(encoding="utf-8"))
bad = [p for p, h in d["files"].items() if hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() != h]
assert not bad, bad
print("Verified", len(d["files"]), "source files")
PY

# 2. 编译、诊断、示例 Schema 校验与全量回归测试（当前 168 项用例）
python3 -m compileall -q scripts tests
python3 scripts/doctor.py
python3 scripts/brand_registry.py validate --profile-file examples/sample-profile.json
python3 -m unittest discover -s tests -v

# 3. 确定性白名单打包校验（输出路径必须放在仓库目录之外，包内附带 SHA256SUMS.txt）
python3 scripts/package_skill.py --out /tmp/brand-takedown-a.zip
python3 scripts/package_skill.py --out /tmp/brand-takedown-b.zip
cmp /tmp/brand-takedown-a.zip /tmp/brand-takedown-b.zip
```

`package_skill.py` 仅按脚本内白名单打包通用源码、模板与文档，**不会夹带私有品牌或案件数据**，并在生成的可复现 `.zip` 压缩包内写入 `brand-takedown/SHA256SUMS.txt` 清单。

### 自动化测试范围说明

自动化测试套件（`tests/`）使用完全脱敏的合成品牌数据、Mock 外部网络响应（如 DoH / RDAP 返回载荷）、仅绑定本机 loopback 的临时 HTTP 服务及内存合成 PNG/BMP 图像验证程序逻辑与负向边界，**不会向真实品牌、平台或执法机构发出任何网络请求或投诉**。在真实投入维权作业前，针对企业邮箱 `Send-As` 发件权限、公网实时 RDAP/DoH 返回兼容度、macOS `/usr/bin/sips` 对特定图片的转码表现及目标法域法律合规要求，仍需结合真实账号与律师意见独立验证。

---

## 社区治理与许可

- 开发规范与 PR 提交检查清单见 [贡献指南](CONTRIBUTING.md)
- 漏洞披露、私有存储要求与数据防泄漏规范见 [安全政策](SECURITY.md)
- 社区协作准则见 [行为准则](CODE_OF_CONDUCT.md)
- 开源许可协议见 [LICENSE](LICENSE)
