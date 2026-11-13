# brand-takedown

brand-takedown 是一个品牌维权 Skill，用于采集网站证据、生成投诉材料和跟进案件进度。

按品牌管理权利资料，将目标网址、证据、投诉通道和回执归入同一案件。Agent 调用脚本完成取证和材料整理，你审核后提交，再记录处理结果。

版本动态见 [更新日志](CHANGELOG.md) 与 [GitHub Releases](https://github.com/zlxmygit/brand-takedown/releases)。

---

## 它能帮品牌和运营解决什么问题？

| 业务场景 | 能为你做什么 |
| --- | --- |
| **品牌资产一次建档** | 统一保管企业主体、官方与授权白名单域名（防止误投诉自家站点或授权经销商），以及商标、版权、外观专利证书和公开归档代理联系人 |
| **涉案页面快速留证** | 抓取侵权网站快照并固定原始文件清单，自动补全域名注册商、托管服务器及网络归属线索；支持用本地密钥签名防止证据被误改 |
| **盗图与视觉抄袭初筛** | 无需安装额外看图软件，直接比对官网产品原图和山寨站截图的视觉相似度，帮你快速挑出重点抄袭页面 |
| **合规起草投诉函（带隐私保护）** | 内置美国 DMCA、欧盟 DSA、商标/假货/支付欺诈等投诉模板；如果某个平台会公开投诉内容（如 **Lumen Database** 公共档案库），在请求中启用公开归档模式后，使用已配置的代理联系人生成署名 |
| **工单催办与下线巡检** | 自动统计哪些投诉超时未回复该催办、哪些被要求补充材料；批量复查山寨网址是否真正打不开，或是否已被域名注册商冻结（如 `clienthold` 停解析状态） |
| **仿冒域名提前预警** | 除了盯紧新签发 HTTPS 证书的域名，还能按品牌名自动推演“错拼字母、加连字符、仅配置钓鱼邮箱”的近似假域名，列进待核实清单提醒人工处理 |

---

## 安装与接入

### 运行环境
- 一台 **Mac 或 Linux** 电脑，安装 **Python 3.11 或更高版本**。
- 无需额外安装第三方依赖包；品牌和案件数据请保存在电脑**本地硬盘**（不要放在共享网盘或同步盘目录中，避免多人/多端写文件冲突）。

### 下载与环境检查
在终端运行以下命令克隆仓库并检查本机是否就绪：

```bash
git clone https://github.com/zlxmygit/brand-takedown.git
cd brand-takedown
python3 scripts/doctor.py
```

只要返回结果中出现 `"ok": true`，说明本机环境已经准备好了（也可以去 [GitHub Releases](https://github.com/zlxmygit/brand-takedown/releases) 下载源码压缩包解压使用）。

### Agent 和邮箱接入
- **挂载 Skill**：把整个 `brand-takedown/` 文件夹放进你使用的 AI 助手 Skill 目录（例如 Antigravity、Claude Code、Codex 等，保持内部文件结构完整）。平时不用自己敲复杂命令行，直接跟 AI 对话让它调用脚本即可。
- **邮箱与截图配合方式**：
  - 本 Skill 只生成待发送的 `.eml` 邮件草稿，不保存邮箱密码也不自动发信。如果公司使用**企业邮箱并转发到 Gmail**，可以在 AI 工具里配合完成验证后的 Gmail `Send-As` 企业发件别名来发信，或用本地邮箱客户端打开 `.eml` 草稿确认无误后手动发送。
  - 遇到需要登录、滑块验证或动态渲染才能看到侵权内容的网页，人工或用浏览器截图保存成图片后交给 AI 导入案件即可。

---

## 日常维权 5 步走（附可以直接对 AI 说的话）

> **重要提醒**：实际维权时生成的**品牌档案、权属证书、案件记录、证据截图和邮件草稿**，必须放在仓库之外的个人工作目录（例如 `$HOME/.gemini/brand-protection/`），**绝对不要**放进代码仓库或上传到 GitHub。

### 第 1 步：建一个品牌档案（一次配置，长期复用）

复制仓库里的脱敏示例 [examples/sample-profile.json](examples/sample-profile.json) 到本地工作目录，填写真实的公司名称、官方域名、白名单、商标/版权/外观证明文件，以及（可选但强烈建议的）**公开投诉代理联系人**（`public_filing_agent`，用于应对会公开归档投诉信的机构）。

> **你可以这样对 AI 说：**  
> “请帮我在 `~/.gemini/brand-protection/my-brand` 目录下参考 `brand-takedown` 初始化一个品牌档案，官方域名是 `brand.example`，把我们的商标证书和公开代理联系信息也加进去，并检查格式是否合规。”

<details>
<summary>给技术支持或需手动排查时的建档命令（点击展开）</summary>

```bash
mkdir -p "$HOME/.gemini/brand-protection/example-brand"
cp examples/sample-profile.json "$HOME/.gemini/brand-protection/example-brand/input.json"
export BRAND_TAKEDOWN_REGISTRY="$HOME/.gemini/brand-protection/registry.json"

# 编辑填入真实资料后校验并注册（brand_slug 需与 --slug 一致；target_markets 支持 US/CA/EU/UK/AU/CN_EXPORT/GLOBAL）
python3 scripts/brand_registry.py validate --profile-file "$HOME/.gemini/brand-protection/example-brand/input.json"
python3 scripts/brand_registry.py init --slug example-brand \
  --data-dir "$HOME/.gemini/brand-protection/example-brand" \
  --profile-file "$HOME/.gemini/brand-protection/example-brand/input.json"

# 查看已建档品牌 / 校验目标是否误触官方白名单
python3 scripts/brand_registry.py list
python3 scripts/brand_registry.py check-allowlist --slug example-brand --url "https://suspect.example/product"
```

</details>

---

### 第 2 步：建案、取证和图片比对

拿到可疑商品链接或山寨站网址后，先为它建档立卷，再抓取网页页面、注册商和服务器托管商线索；如果你另外存了高清对比截图，也可以一起导入并做一次图片相似度初筛。

- **每次留证独立存档**：后续补交新截图会自动新增一个快照，**不会覆盖历史记录**，确保时间线清晰。
- **盗图初筛边界**：比对打分（`dHash` 汉明距离，默认阈值 10）用于筛选相似图片；透明像素统一合成到白底，是否真正构成抄袭仍需人眼复核（在 macOS 上可直接比对 PNG/BMP/JPG 等常见图片；在 Linux 上请先转为 PNG 或 BMP）。
- **证据签名（可选）**：设置 `BRAND_TAKEDOWN_HMAC_KEY` 后，新证据使用 HMAC 签名。品牌档案中设置 `"require_evidence_hmac": true`，或设置环境变量 `BRAND_TAKEDOWN_REQUIRE_HMAC=1`，可在取证、审批、邮件导出和回执登记时持续要求签名。密钥通过运行环境提供，不写入仓库。

> **你可以这样对 AI 说：**  
> “帮我对 `https://suspect.example/product` 建一个版权抄袭案件，马上抓取网页内容和域名/服务器信息；再把我桌面上的 `original.png` 和刚截的 `suspect.png` 做一次盗图相似度比对。”

<details>
<summary>建案、抓包、加截图与盗图比对命令（点击展开）</summary>

```bash
# 1. 创建案件（侵权类型支持 COPYRIGHT_CLONE / TRADEMARK_IMPERSONATION / COUNTERFEIT_GOODS / DESIGN_PATENT_COPY / PHISHING_OR_FAKE_TRACKING）
python3 scripts/case_manager.py create --slug example-brand \
  --url "https://suspect.example/product" --types COPYRIGHT_CLONE

export CASE_DIR="填入上一步返回的 case_dir 路径"

# 2. 抓取网页及域名/IP归属线索
python3 scripts/recon_target.py run --slug example-brand \
  --case-dir "$CASE_DIR" --url "https://suspect.example/product"

# 3. 补充本地截图或其他材料，并校验证据清单未被修改（如启用本地签名可附带 --require-hmac）
python3 scripts/recon_target.py add-evidence --slug example-brand \
  --case-dir "$CASE_DIR" --url "https://suspect.example/product" \
  --source "$HOME/evidence/screenshot.png"
python3 scripts/recon_target.py refresh-manifest --slug example-brand --case-dir "$CASE_DIR"

# 4. 盗图视觉相似度比对（数值越小越相似）
python3 scripts/recon_target.py compare-images --slug example-brand --case-dir "$CASE_DIR" \
  --original "$HOME/brand/original.png" --suspect "$HOME/evidence/suspect.png" --threshold 10
```

</details>

---

### 第 3 步：核对举报通道并起草投诉材料

先去服务商（域名注册商、托管服务器、CDN、收款支付机构或建站 SaaS 等）**官网**核对真实的侵权投诉入口，再让 AI 按对应法律路线起草投诉包：

- **别直接信山寨站页面上的邮箱**：必须核实服务商官方公示页面来源。
- **防隐私外泄检查**：对于可能将投诉文本转给涉案商家或纳入 **Lumen Database** 公开档案库的渠道，建议告诉 AI 启用“公开归档代理署名”（对应请求里的 `public_archive_expected`），保护经办人姓名、真实邮箱和办公地址不被搜索引擎公开收录。
- **时效性检查**：权利材料与渠道联系方式的核验记录需在最近 **30 天**内。

> **你可以这样对 AI 说：**  
> “我已经核实过这家托管主机商的官方投诉邮箱是 `abuse@provider.example`，来源页是 `https://provider.example/legal/dmca`。请登记这条通道，按美国 DMCA 版权投诉格式引用刚才抓取的证据起草投诉材料；如果对方可能公开归档，请自动切换成我们的公开代理联系人署名。”

<details>
<summary>通道登记、请求 JSON 字段与投诉包生成命令（点击展开）</summary>

```bash
# 1. 登记官方核实后的投诉通道（--channel-class 可选 ENFORCEMENT_SLA 或 REGULATORY_FILING）
python3 scripts/case_manager.py add-channel --slug example-brand \
  --case-dir "$CASE_DIR" --channel-id host \
  --channel-class ENFORCEMENT_SLA --category hosting \
  --provider "服务商官方名称" --endpoint "abuse@provider.example"

# 2. 按 request.json 生成投诉包（总附件上限 15 MiB）
python3 scripts/packets.py --slug example-brand --case-dir "$CASE_DIR" \
  prepare --request-file "$HOME/.gemini/brand-protection/example-brand/request.json"
```

**常用投诉路线 (`route`) 与主张类型 (`claims[].kind`) 对照**：
- `COPYRIGHT_NOTICE` → `COPYRIGHT`（现行版权模板适用 `US` 美国 DMCA）
- `TRADEMARK_NOTICE` → `TRADEMARK` / `COUNTERFEIT`
- `DESIGN_NOTICE` → `DESIGN`
- `ABUSE_REPORT` → `PHISHING`
- `DSA_NOTICE` → 上述各类均可（要求地区 `EU` 且服务商角色 `hosting`）
- `SAFETY_REFERRAL` → `PRODUCT_SAFETY`（需填写 `specific_requirement_and_defect`）
- `REGULATORY_FILING` → 监管通报，上述各类均可（含 `GLOBAL` / `CN_EXPORT` 市场）

**公开归档隐私防泄漏开关（写入 `request.json`）**：
- `public_archive_expected`: `true` 时强制切换使用品牌档案中的 `public_filing_agent`；若未配置代理则会直接报错拦截，除非明确经过隐私审查后额外传入 `allow_primary_signatory_in_public_archive: true`。
- 完整字段及可参考测试结构见 [`tests/common.py`](tests/common.py)。

</details>

---

### 第 4 步：人眼核对正文、批准出稿并回填发送回执

投诉包生成后，一定要打开生成的 `notice.txt` 亲自过一遍**正文措辞、收件人、署名和附件**，没问题再批准确认并导出 `.eml` 草稿。

- **审批有效期**：如果后来修改过任何文字或附件，或者超过 **7 天** 未发出，需要重新审校批准。
- **收到回执再记账**：通过企业邮箱（或已配置好企业 `Send-As` 的 Gmail）**实际发出去以后**，再让 AI 把服务商工单回执号和真实发送时间登记回案件，系统才会开始按服务商类别倒计时（如支付/SaaS/钓鱼 48 小时，注册商/主机/CDN 72 小时，搜索广告 120 小时）。

> **你可以这样对 AI 说：**  
> “我检查过投诉函正文、收件邮箱和附件了，全部确认无误，请批准并生成 `.eml` 草稿（或通过我们的企业邮箱别名发出去）。刚发完拿到的工单回执是 `TICKET-9527`，发送时间按刚才记录。”

<details>
<summary>审批、导出 EML 与回填回执命令（点击展开）</summary>

```bash
export PACKET_ID="填入上一步返回的 packet_id"
export PACKET_SHA256="填入上一步返回的 packet_sha256"

# 1. 记录人工审批结果并导出未发送草稿（带 X-Unsent: 1）
python3 scripts/packets.py --slug example-brand --case-dir "$CASE_DIR" approve \
  --packet-id "$PACKET_ID" --reviewer "审批人姓名" \
  --reviewed-digest "$PACKET_SHA256" --confirm-human-review

python3 scripts/build_eml.py --slug example-brand --case-dir "$CASE_DIR" \
  --packet-id "$PACKET_ID"

# 2. 实际发送成功后再记录回执（时间须带时区，如 2026-11-13T15:00:00+08:00）
python3 scripts/case_manager.py submit --slug example-brand \
  --case-dir "$CASE_DIR" --channel-id host --packet-id "$PACKET_ID" \
  --submission-ref "$ACTUAL_RECEIPT" --sent-at "$ACTUAL_SENT_AT"
```

</details>

---

### 第 5 步：催办、巡检和域名扫描

维权发出后，每天或每周定期让 AI 跑一次汇总、巡检和域名扫描：

- **查待办与催办**：一眼看清哪些案件已经超期需要二轮/三轮升级催办，哪些被服务商要求补充材料（`NEED_MORE_INFO`）。
- **下线复核不瞎猜**：巡检脚本会检查所有关联网址和隐匿跳转域，不会因为某一页偶发 404 就轻易判定“维权已彻底解决”；打开 `--check-rdap` 还能核对域名是否被注册商冻结解析（出现 `clienthold` / `serverhold` 状态）。
- **收到反通知（Counter-Notice）必须报警**：一旦收到对方提出异议或反通知，立即登记来源凭证；系统会自动暂停该案的常规催办节奏、单列高优法律待办，并按 10–14 个工作日估算一个**仅供参照的窗口期**（具体法律时效与是否起诉须由律师确认）。
- **盯防近似仿冒域名**：定期运行雷达扫描，把排查出的新域名或近似拼写域名统一放入“待复核”队列，人工确认后决定是立即建案取证（`CONFIRMED_FOR_REVIEWED_CASE`）、误报忽略（`REJECTED`）还是授权域名放行（`AUTHORIZED`）。

> **你可以这样对 AI 说：**  
> “帮我拉一下这个品牌现在所有的到期催办待办，跑一遍所有涉案站点的下线巡检（顺便看下注册商冻结状态）；然后再扫描一次近期有没有近似拼写或仅配了邮箱的仿冒新域名。”

<details>
<summary>日常巡检、反通知录入与域名雷达分诊命令（点击展开）</summary>

```bash
# 查看待办清单与案件总览
python3 scripts/case_manager.py due --slug example-brand
python3 scripts/case_manager.py summary --slug example-brand

# 批量巡检目标存活及域名 RDAP 冻结状态（单案可使用 probe --case-dir "$CASE_DIR"）
python3 scripts/check_liveness.py patrol --slug example-brand --check-rdap

# 更新工单进展 / 登记关联隐匿域 / 规划下一轮升级（仅计划状态，不自动发信）
python3 scripts/case_manager.py update-channel --slug example-brand --case-dir "$CASE_DIR" \
  --channel-id host --status NEED_MORE_INFO --ticket-ref "TICKET-9527"
python3 scripts/case_manager.py add-cloak --slug example-brand --case-dir "$CASE_DIR" --domain "cloak-pay.example"
python3 scripts/case_manager.py escalate --slug example-brand --case-dir "$CASE_DIR" --channel-id host

# 收到反通知时登记法律待办，并在律师给出意见后关闭
python3 scripts/case_manager.py counter-notice --slug example-brand --case-dir "$CASE_DIR" \
  --channel-id host --received-at "2026-11-13T15:30:00+08:00" \
  --summary "收到对方反通知邮件，转交法务评估应对" --source-ref "eml-msg-id-or-ticket"
python3 scripts/case_manager.py resolve-legal --slug example-brand --case-dir "$CASE_DIR" \
  --task-id "$LEGAL_TASK_ID" --reviewer "法务审核人" --disposition "完成律师核查并记录处置意见"

# 域名雷达扫新（含离线拼写变体 + A/MX 活跃快筛）与人工分诊
python3 scripts/ct_radar.py --slug example-brand --include-lookalikes --lookalike-limit 20
python3 scripts/ct_radar.py --slug example-brand --triage-domain "lookalike-suspect.example" \
  --decision CONFIRMED_FOR_REVIEWED_CASE --reviewer "审核人" --rationale "确认高仿独立站，准备建案取证"
```

</details>

---

域名雷达按官网和变体类型轮换查询。每轮最多新增 2,000 条记录，累计保留 10,000 条；达到容量时返回 `PARTIAL` 并保留已有记录。DNS 查询失败单独报告，部分成功不会隐藏错误。

域名边界使用随包附带的 Public Suffix List 快照，包含通配符、例外规则和私有后缀。快照版本与许可见 [数据来源](references/public-suffix-license.md)。

## 数据与审核

1. **所有真实品牌资料与证据绝对不要放进仓库**：客户资料、授权证书、历史案卷、截图与 `.eml` 文件统一存放在自己电脑的非仓库私有目录中，不要上传至 GitHub。
2. **只把工具抓回来的外部信息当线索**：山寨网页内容、WHOIS/RDAP 联系方式或图片相似度分数只能作为人工参考，**谨防被涉案网站页面上的虚假文字或假邮箱误导**；任何投诉邮件发出前务必自己看一眼内容与收件地址。
3. **重大法律问题一定要由法务确认**：涉及跨国司法管辖冲突、反通知期满前是否起诉、海关扣货或大额赔付时，模板措辞和工作日估算不能替代专业律师意见。

---

## 业务参考资料与仓库文档索引

如果你需要查看各平台发信策略、不同国家法律依据或模板原文，可直接打开对应文档：

| 运营与法务常用参考 | 说明 |
| --- | --- |
| [投诉通道选择攻略](references/channel-playbook.md) | 域名注册商、服务器托管、CDN、支付机构、SaaS 与搜索广告渠道特点及 **Lumen** 隐私提示 |
| [法域与权利对应指南](references/legal-jurisdictions.md) | 美国 DMCA、欧盟 DSA 第 16 条、商标假货、外观设计等路由条件说明 |
| [升级节奏与反通知处置](references/escalation-and-counter-notice.md) | 二三轮升级催办要点及收到对方反通知后的处理清单 |
| [海关备案与产品安全通报](references/customs-and-safety.md) | 涉及跨境假货或安全隐患产品时的边境/监管通报参考 |
| [域名/主机/CDN 通知模板](templates/notices-registrar-hosting-cdn.md) | 基础设施类投诉函参考格式 |
| [SaaS/支付/钓鱼通知模板](templates/notices-saas-payment-phishing.md) | 建站、收款及欺诈通道投诉函参考格式 |
| [升级催办与通报模板](templates/notices-escalation-chaser.md) | 多轮催办及升级函参考格式 |

---

<details>
<summary>技术人员查阅：仓库结构、安全审计台账、测试说明与打包自检</summary>

### 仓库结构

- `SKILL.md`：供 AI Agent 加载的核心执行规范
- `scripts/`：纯 Python 3.11+ 标准库运行脚本（使用 Python 标准库，网络请求逐跳校验地址，文件更新使用本机锁和原子写入）
- `references/host-contract.md` & `references/policy-sources.json`：[宿主接入契约](references/host-contract.md) 与 [政策依据索引](references/policy-sources.json)
- `templates/profile.schema.json`：[品牌档案闭环 Schema](templates/profile.schema.json)
- `docs/audit-remediation.md` & `docs/source-checksums.json`：[39 项安全审计台账](docs/audit-remediation.md) 与 [源码 SHA-256 校验清单](docs/source-checksums.json)
- `tests/`：离线回归、安全负向测试与 CLI 集成测试套件（运行下方命令查看当前测试数量；测试过程中网络与 RDAP/DoH 响应采用 Mock 数据，投入真实生产前需结合企业 `Send-As` 发件权限与真实公网样本验证）

### 历史旧版案件迁移提示

当前案件目录结构为 `schema_version: 2`。请勿就地覆写早期的旧目录：应先完整备份旧目录，在新的私有目录重新建档建案，再使用 `recon_target.py add-evidence` 作为新快照导入历史证据文件并保留原始出处说明，未结案的反通知与邮件回执须单独核对录入待办。

### 开发与发布检验命令（与 `.github/workflows/ci.yml` 对齐）

```bash
python3 - <<'PY'
import hashlib, json, pathlib
d = json.loads(pathlib.Path("docs/source-checksums.json").read_text(encoding="utf-8"))
bad = [p for p, h in d["files"].items() if hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() != h]
assert not bad, bad
print("Verified", len(d["files"]), "source files")
PY
python3 -m compileall -q scripts tests
python3 scripts/doctor.py
python3 scripts/brand_registry.py validate --profile-file examples/sample-profile.json
python3 -m unittest discover -s tests -v
python3 scripts/package_skill.py --out /tmp/brand-takedown-a.zip
python3 scripts/package_skill.py --out /tmp/brand-takedown-b.zip
cmp /tmp/brand-takedown-a.zip /tmp/brand-takedown-b.zip
```

> `package_skill.py` 仅按白名单打包公开源码和文档，并在生成的可复现 `.zip` 压缩包内部附加 `SHA256SUMS.txt` 清单，不会夹带任何私有运行数据。开发规范见 [贡献指南](CONTRIBUTING.md)、[安全政策](SECURITY.md)、[行为准则](CODE_OF_CONDUCT.md) 与 [开源许可](LICENSE)。

</details>
