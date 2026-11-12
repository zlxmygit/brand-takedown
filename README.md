# brand-takedown

**人工监督的品牌维权取证与投诉草稿 Skill；不是无人值守封站系统。**

本次安全重构将案件身份、证据快照、投诉审批、真实提交回执和法律提醒分开。
不保证封禁结果，不自动发送邮件、提交表单、购买商品或触发公开存档。
旧 `v1.0.0` 的自动化及法律效果承诺不适用于本实现。

## 环境与安装

Python **3.11+**，Linux/macOS，本机私有 POSIX 文件系统。Python 运行时零第三方包依赖；
不再依赖写死路径的 curl、dig、whois、openssl 命令。不要在 NFS、共享云盘或多主机上写同一状态目录。

```bash
git clone https://github.com/zlxmygit/brand-takedown.git
cd brand-takedown
python3 scripts/doctor.py
python3 -m unittest discover -s tests -v
```

将仓库或经过校验的通用包放到宿主真正支持的 Skill 目录。不同 Agent 的安装目录、
工具名及调度权限不相同；本仓库不宣称固定 Gmail 命令或 `/schedule` 在任意宿主可用。
详见 [宿主能力契约](references/host-contract.md)。

## 安全边界

|模块|行为|
|---|---|
|品牌与案件|UUID 身份绑定；规范化域名用于同域合并；目录不可跨品牌复用|
|状态写入|本机线程/进程锁、唯一临时文件、fsync、原子替换、revision 冲突检查|
|HTTP|每跳白名单及公网地址校验、连接 IP 固定、TLS 校验、大小/时间/跳转限制|
|取证|每次独立 `CAP-*` 目录；原始字节、响应元数据、报告一起封存；旧清单只验证|
|存活|检查全部 URL 与关联线索；不把空 DNS、自报停用文字或单页 404 当作整案下线|
|法律提醒|独立待办；反通知恢复窗口仅做周末调整估算，必须由律师确认|
|投诉|逐项事实/证据/权利/属地校验；独立人工审批绑定正文、收件目标和附件摘要|
|邮件|只生成未发送 EML；发件账户认证和真实发送不在本包中|
|CT|错误与零发现分开；待处置候选持续显示，只有明确人工分类才退出队列|

代理、伪装 Referer、自动 Wayback 发布和自动浏览器结账已关闭。
哈希清单不是可信时间戳、公证或不可篡改存储；同一账户可修改整个数据目录，因此仍需备份、
访问控制及按案件要求采用外部可信存证。网络出口防火墙应作为第二层防御。

## 使用流程

### 1. 私有品牌建档

复制 `examples/sample-profile.json` 到仓库外，填写真实资料；示例不含可用于真实投诉的权利凭证。
`brand_slug` 必须与 `--slug` 一致。证书相对路径在注册时按 `--data-dir` 解析，建议使用绝对路径。

```bash
export BRAND_TAKEDOWN_REGISTRY="$HOME/.gemini/brand-protection/registry.json"
python3 scripts/brand_registry.py validate --profile-file "$HOME/private-profile.json"
python3 scripts/brand_registry.py init --slug example-brand \
  --data-dir "$HOME/.gemini/brand-protection/example-brand" --profile-file "$HOME/private-profile.json"
```

也可在每个 CLI 子命令之前传 `--registry <path>`。实际数据必须在仓库外；`.gitignore` 只是辅助，
不是保密保证。不要把档案、证书、案件、生成的邮件或完整审计运行数据提交到 Git。

### 2. 建案与取证

```bash
python3 scripts/case_manager.py create --slug example-brand \
  --url "https://suspect.example/product" --types COPYRIGHT_CLONE
# 使用上一步返回的真实 case_dir。
python3 scripts/recon_target.py run --slug example-brand --case-dir "$CASE_DIR" \
  --url "https://suspect.example/product"
python3 scripts/recon_target.py refresh-manifest --slug example-brand --case-dir "$CASE_DIR"
```

`.example` 是文档占位域名，不提供真实取证成功样例。网络失败会返回非零退出码并保存失败记录，
不会把空页面变成有效取证。截图请通过 `add-evidence --source <file>` 追加为新快照，不要修改旧快照。
`refresh-manifest` 改为验证命令，发现修改就报错，不能用来接受新哈希。

### 3. 草稿通道、结构化主张与审批

```bash
python3 scripts/case_manager.py add-channel --slug example-brand --case-dir "$CASE_DIR" \
  --channel-id host --channel-class ENFORCEMENT_SLA --category hosting \
  --provider "Independently verified provider" --endpoint "abuse@provider.example"
```

`packets.py prepare` 读取私有请求 JSON，字段为：`channel_id`、`route`、`jurisdiction`、`subject`、
`provider_role`、`scope_reason`、`endpoint_source_url`、`endpoint_verified_by`、`endpoint_verified_at`、
`authorization_fair_use_review`、`rights_verified_by`、`rights_verified_at`、`claims`。
核验时间须带时区并在最近 30 天内；这是内部复核期限，不是平台或法律保证。

每个 claim 包含 `kind`、`target_url`、`statement`、`legal_basis`、`comparison_or_observed_facts`、
`evidence: [{"capture_id": "真实快照ID", "filename": "raw.bin"}]`。
知识产权主张还需要 `right_index`，指向品牌档案相应权利数组中的项目。
安全主张另需 `specific_requirement_and_defect`，不能直接复制品牌档案的品类风险描述。
可参考 `tests/common.py` 中完全合成的请求结构，但不得把测试事实用于真实投诉。

支持 `COPYRIGHT_NOTICE`、`TRADEMARK_NOTICE`、`DESIGN_NOTICE`、`ABUSE_REPORT`、`DSA_NOTICE`、
`SAFETY_REFERRAL`、`REGULATORY_FILING`。当前 DMCA 模板只用于经审核的美国版权主张；
DSA Article 16 路由要求 EU 适用范围和 hosting 角色，不根据英国地址或欧元标价自动认定。

```bash
python3 scripts/packets.py --slug example-brand --case-dir "$CASE_DIR" prepare --request-file "$REQUEST_JSON"
# 展示正文、收件目标、附件和摘要，并获得真实授权人明确同意后：
python3 scripts/packets.py --slug example-brand --case-dir "$CASE_DIR" approve \
  --packet-id "$PACKET_ID" --reviewer "实际审核人" --reviewed-digest "$PACKET_SHA256" --confirm-human-review
python3 scripts/build_eml.py --slug example-brand --case-dir "$CASE_DIR" --packet-id "$PACKET_ID"
```

审批是本地流程记录，不是数字签名或授权身份认证。邮件带 `X-Unsent: 1`，不执行发送。
From 头不能替代真实企业发件账户、SPF/DKIM 或 Send-As 权限。任何正文、附件、目标或品牌资料变化
都需要重新生成和审批。审批超过 7 天需重审。

只有实际人工发送/提交后，才能记录：

```bash
python3 scripts/case_manager.py submit --slug example-brand --case-dir "$CASE_DIR" \
  --channel-id host --packet-id "$PACKET_ID" --submission-ref "$ACTUAL_RECEIPT" --sent-at "$ACTUAL_SENT_AT"
```

### 4. 巡检、补件和反通知

`check_liveness.py patrol --slug <slug>` 逐案隔离错误。`case_manager.py due --slug <slug>` 同时输出
跟进、补件、Tier-3 复核和法律待办。`escalate` 只计划草稿，不虚构已发送的升级事件。
`counter-notice` 要求 `--source-ref`；`--provider-received-at` 和 `--provider-timezone` 已知时才做
10–14 工作日的**非法律截止估算**。未知起算日就立刻请求律师核对，不伪造具体期限。
`resolve-legal` 需要审核人和书面处置理由，网络巡检永远不能代替它。

### 5. 雷达与封装

```bash
python3 scripts/ct_radar.py --slug example-brand
python3 scripts/package_skill.py --out /tmp/brand-takedown-reviewed.zip
```

CT 候选持续保留到 `--triage-domain ... --decision ... --reviewer ... --rationale ...`。
打包器只收录显式白名单文件，附 SHA256SUMS；不会递归打包私有运行目录。打包不是发布 Release。

## 兼容性与迁移

这是安全性优先的破坏性接口修订：Python 最低版本变为 3.11；案件 schema 为 2；
旧的 `--status SUBMITTED`、任意 `--case-dir`、未审批 EML CLI、代理和自动归档路径不再接受。

**不自动就地迁移历史案件。** 先完整备份原私有目录和注册表，在隔离副本上审查原品牌、目标、
提交回执和法律待办；使用新的私有目录及新的注册表重新建档、建案。旧证据只能作为标明来源的
历史文件通过 `add-evidence` 引入，不能把导入时间冒充原取证时间，也不能把旧哈希重新认定为真实。
旧反通知须优先人工核对并录入独立待办；旧邮件回执单独保留。历史上已被覆盖的证据无法由代码恢复。

## 验证与限制

```bash
python3 -m compileall -q scripts tests
python3 scripts/doctor.py
python3 -m unittest discover -s tests -v
```

测试使用合成品牌、模拟外部响应和仅绑定 loopback 的本地 HTTP 服务；不发送真实投诉。
见 [39 项审计整改映射](docs/audit-remediation.md) 和 [安全政策](SECURITY.md)。
真实 Gmail、浏览器、支付平台、监管门户、各法域司法程序仍需独立集成/专业验证。
