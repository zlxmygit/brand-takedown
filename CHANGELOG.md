# 更新日志

## v1.4.0

- 在 `recon_target.py` 新增零依赖 64-bit 差异感知哈希 (`dHash`) 图片比对能力与 `compare-images` 子命令：支持纯标准库解码 8-bit PNG（过滤类型 `0..4`、色彩类型 `0/2/3/4/6`）与未压缩 `8/24/32`-bit BMP（macOS 可回退至 `/usr/bin/sips`），输出汉明距离与 `VISUAL_SIMILARITY_HINT_NOT_PROOF_OF_INFRINGEMENT` 辅助复核线索。
- 新增可选本地 `BRAND_TAKEDOWN_HMAC_KEY` 环境变量驱动的 `HMAC-SHA256` 证据清单签名与校验机制，以及 `refresh-manifest --require-hmac` 强制验签开关（明确区分本地完整性校验与外部可信时间戳 TSA）。

## v1.3.0

- 升级 `ct_radar.py`：新增零依赖离线拼写抢注与仿冒变体生成器（漏字母、邻位换位、字符重复、连字符增删、ASCII 同形视觉替换与商业组合词前缀/后缀），严格排除品牌白名单与内部保留域。
- 新增基于安全 HTTPS DoH 的受控域名 `A`/`MX` 存活快筛 (`--include-lookalikes` / `--lookalike-limit`)，捕捉尚未申请 SSL 证书或仅配置仿冒发信 `MX` 记录的活跃钓鱼域，沿用 `PENDING_REVIEW` -> 人工 `triage` 状态机。

## v1.2.0

- 新增 **Lumen Database** 公共档案防隐私暴露与授权代理署名护栏：`profile.schema.json` 与 `brand_registry.py` 新增可选 `public_filing_agent` 代理署名人/商用邮政地址配置及格式校验。
- `packets.py` 支持 `public_archive_expected` 与 `use_public_filing_agent` 安全切换机制：对预期公开归档渠道自动改用代理署名（未配置代理时 fail-closed 拦截，除非经隐私复核显式允许主署名人）。
- 在 `SKILL.md`、`channel-playbook.md`、`legal-jurisdictions.md`、`policy-sources.json` (`S12`) 及投诉文书模板补全公开披露隐私自检护栏。

## v1.1.0

- 增强域名 RDAP 查询：支持子域名逐级回退至可注册主域（兼容常见二级公共后缀），并结构化提取注册商、IANA ID、注册/到期时间、abuse 邮箱/电话、NS 与归一化 `status_codes`。
- 新增受控公网 IP RDAP（IANA IPv4/IPv6 bootstrap 最长前缀匹配）与 Google DoH Team Cymru TXT ASN 归属补全，写入不可信线索 `ip_intel` 字段（`HOSTING_HINT_NOT_PROOF_OF_ATTRIBUTION`），零外部 `dig`/`whois` 依赖。
- 增强 `check_liveness.py`：归一化 `client hold` / `clientHold` 等注册状态并支持 `--check-rdap` 按主机去重查询注册冻结信号，同时保持人工复核边界。

## v1.0.1

- 修复案件隔离、域名冲突和并发写入问题。
- 加强网络访问校验与证据快照完整性验证。
- 完善投诉审批、反通知提醒和案件跟进流程。
- 优化域名发现与查询，补充 150 项回归测试。
