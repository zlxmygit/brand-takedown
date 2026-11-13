# 更新日志

## v1.1.0

- 增强域名 RDAP 查询：支持子域名逐级回退至可注册主域（兼容常见二级公共后缀），并结构化提取注册商、IANA ID、注册/到期时间、abuse 邮箱/电话、NS 与归一化 `status_codes`。
- 新增受控公网 IP RDAP（IANA IPv4/IPv6 bootstrap 最长前缀匹配）与 Google DoH Team Cymru TXT ASN 归属补全，写入不可信线索 `ip_intel` 字段（`HOSTING_HINT_NOT_PROOF_OF_ATTRIBUTION`），零外部 `dig`/`whois` 依赖。
- 增强 `check_liveness.py`：归一化 `client hold` / `clientHold` 等注册状态并支持 `--check-rdap` 按主机去重查询注册冻结信号，同时保持人工复核边界。

## v1.0.1

- 修复案件隔离、域名冲突和并发写入问题。
- 加强网络访问校验与证据快照完整性验证。
- 完善投诉审批、反通知提醒和案件跟进流程。
- 优化域名发现与查询，补充 150 项回归测试。
