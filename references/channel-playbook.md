# 通道与信息披露审核

**先保存必要证据，再决定投诉。任何梯队都不能保证对方不知情。**
Shopify 的版权政策明确提示投诉及联系方式可能提供给发布者；其他服务商也应逐个核验。

## 通道不是自动封禁指令

Shopify / 其他 SaaS：独立选择版权、商标或真实欺诈路径，使用精确内容 URL。
Stripe / PayPal / 收单方：核对真实服务商及收款关联；公钥不是秘密，也不能单独证明商户归属或违法。
Safe Browsing / 反钓鱼：只提交确有支撑的安全事实，不把一切商业争议标为钓鱼。
Cloudflare / CDN / 主机：先确认当前角色；边缘 IP 不等于源站，CDN 也可能提供不同托管产品。
注册商：使用 RDAP/官方站验证联系人，区分 DNS Abuse 与民事域名争议，不预设必须 clientHold。
海关/CPSC/其他监管：使用 REGULATORY_FILING，仅提交经核实线索，不套商业催办函。

## 每案维护真实联系来源

登记 `target_endpoint` 前由审核人访问服务商官方政策页，保存 `endpoint_source_url`、
`endpoint_verified_by` 和带时区的 `endpoint_verified_at`。不能仅从可疑网站或转发邮件抄地址。
核验超过 30 天需重做；该期限是本工具保守复核策略，不代表官方入口在此期间必然有效。

本仓库不再分发大量未经逐个验证的投诉邮箱。以下仅作为政策入口，不是自动收件人列表：

- Shopify copyright: https://help.shopify.com/en/manual/compliance/intellectual-property/copyright-policy
- Shopify trademark: https://help.shopify.com/en/manual/compliance/intellectual-property/trademark-trade-dress-policy
- ICANN RDAP: https://www.icann.org/en/contracted-parties/registry-operators/resources/registration-data-access-protocol
- ICANN DNS Abuse advisory: https://www.icann.org/en/contracted-parties/advisories/documents/advisory-compliance-with-dns-abuse-obligations-in-the-registrar-accreditation-agreement-and-the-registry-agreement-05-02-2024-en

## 顺序与回执

证据固化 → 事实/权利审核 → 披露风险确认 → packet prepare → 人工审批 → 人工真实提交 → 记录回执。
`DRAFT_CREATED` 不等于 `SUBMITTED`。软件内部 48/72/120 小时只作为跟进目标，不是服务商承诺、
法定期限或自动责任认定。不要对同一证据重复轰炸多个邮箱。
