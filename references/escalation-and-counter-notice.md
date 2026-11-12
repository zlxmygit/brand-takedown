# 跟进与反通知处置

## 三阶跟进只是工作流

Tier 1 是初次已提交材料；Tier 2 是基于新事实的跟进；Tier 3 是由人决定的升级或专业评估。
`escalate` 只计划草稿。没有独立审批和真实发送回执，不能更新成已发送升级或重置截止。
NEED_MORE_INFO 留在补件队列；Tier 3 仍保留复核待办，不能无限自动升级。
监管备案不进入商业 SLA 循环。

不要宣称超过内部 48/72/120 小时就必然丧失 Safe Harbor 或承担产品连带责任。
ICANN 的 DNS Abuse 指引要求根据证据、危害及附带损害采取及时适当措施，并不统一规定 clientHold。
UDRP/URS 的资格、合并标准、费用、程序时间及救济均应由相应机构和专业人员逐案核验。

## DMCA Counter-Notice

记录来源消息引用，区分“权利人收到转发时间”和“服务商收到反通知时间”。
17 U.S.C. § 512(g)(2)(C) 涉及服务商收件后的 10–14 工作日恢复窗口和已提起相关法院程序的通知；
普通反驳邮件、换一个投诉分类或怀疑地址不真实不能保证阻止恢复。

软件只在提供服务商收件时间时计算周末调整的窗口估算，字段标明非法律截止：
`WEEKDAYS_ONLY_ESTIMATE_NOT_LEGAL_DEADLINE`。未涵盖节假日、当地计时规则和具体程序事实。
无论起算日是否明确，都立即建立独立 LEGAL_REVIEW 待办，交律师确认并及时采取适当程序。

网站下线、工单解决或定时巡检不能清除这个待办；只有 `resolve-legal` 的具名审核及书面处置可以。
地址核验仅形成待核查事实，不能自动认定伪证。Shopify 商标/商业外观也有回应机制，合格回应后
通常允许重新发布，不能承诺“换轨永久锁死”。

来源（核验日期 2026-11-12）：
- https://www.copyright.gov/512/
- https://help.shopify.com/en/manual/compliance/intellectual-property/trademark-trade-dress-policy
- https://www.icann.org/en/contracted-parties/advisories/documents/advisory-compliance-with-dns-abuse-obligations-in-the-registrar-accreditation-agreement-and-the-registry-agreement-05-02-2024-en
