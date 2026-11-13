# SaaS、支付与安全举报草稿说明

不要直接套用旧版的冻资、永久封店或必然危害断言。使用 `packets.py prepare` 从逐项证据生成草稿，
再由授权人查看具体文字、目标、附件和 packet digest。仅在明确批准后记录 approval。

|类型|必须有的支持|不可自动推断|
|---|---|---|
|COPYRIGHT_NOTICE|原作权属、逐 URL 复制对比、授权/合理使用审核|品牌词出现就盗图|
|TRADEMARK_NOTICE|有效权利、地域、具体冒用/混淆事实|未经授权销售等于假货|
|ABUSE_REPORT|具体凭证/资金诱骗及页面证据|共享支付公钥等于商户违法|
|SAFETY_REFERRAL|具体适用要求和实际观察的缺陷|高风险类别等于不合规|

Shopify 可能通知商家并提供投诉与联系方式，商标回应后也可能允许重新发布。
Stripe/PayPal 的当前官方入口由具名审核人每案核验；本文件不提供未经核验的收件邮箱。
收件主体、正文和附件发生变化即重新审批，EML 不执行发送。

英文措辞方向（不是可直接提交的完整法定通知）：
```text
Please review the specific allegations and supporting evidence identified in the packet.
We request appropriate and proportionate action under the applicable policy or law.
Please acknowledge receipt and advise us of your decision and available review routes.
```

来源：见 [channel-playbook.md](../references/channel-playbook.md) 与 [policy-sources.json](../references/policy-sources.json)。

公开披露自检：主要 SaaS 与搜索服务商可能向涉事商家转发投诉正文及联系信息，或同步收录至 `Lumen Database`；如涉公开归档，请在品牌档案中启用 `public_filing_agent` 并在请求中标记 `public_archive_expected: true`。
