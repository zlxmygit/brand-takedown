# 海关与产品安全：经审核的监管线索

这些通道使用 `REGULATORY_FILING`。不发送商业 SLA 催办、不保证查扣、销毁、冻结资金或全域执法。
本包不自动登录、填写或提交 CBP、CBSA、EUIPO/IPEP、HMRC、GACC、CPSC 或 Safety Gate 表单。

## 海关审核

核对权利属地、备案资格、申请人授权、有效期、所请求地区、货物和物流线索、担保及程序责任。
供应链不在品牌白名单不自动证明是假货，需考虑真实商品、合法转售和适用海关权限。
欧盟 AFA 存在 national/Union 申请之分；Union AFA 的效果与所请求采取行动的成员国有关，
不能宣传为填写一次就自动在全部 27 国扣押。

当前各国官方入口、费用、适用范围必须在真实申报前重新核验。
不使用旧 IP 地址门户或未经证实的统计数字，不以品牌自发黑名单作为最高权重“自证”。
官方 EU AFA 指南：
https://taxation-customs.ec.europa.eu/customs/prohibitions-restrictions/counterfeit-piracy-other-ipr-violations/defend-your-rights_en

## 安全主张审核

品牌产品属于锂电、儿童用品或其他高风险类别，只能提示人工核对适用规范。
要指称具体产品不合规，必须记录产品身份、目标市场、适用法规/标准、可观察缺陷或检测结果，
以及事实限制。不要断言所有假冒产品都缺少 CE/UL，或自动推导平台、支付机构承担连带赔偿。
CE 并非所有商品通用的政府安全认证；具体强制要求需按产品与法域确认。

GPSR Regulation (EU) 2023/988 的远程销售信息要求应核对 Article 19，
并结合制造商是否位于欧盟、适用责任人及专门产品法规，不只引用 Article 16 就声称所有页面违法。
`packets.py` 的 PRODUCT_SAFETY 主张要求 `specific_requirement_and_defect` 与具体证据，
不会自动插入品牌档案中的 hazard_statement_en。

官方来源：
- https://single-market-economy.ec.europa.eu/single-market/goods/ce-marking_en
- https://eur-lex.europa.eu/eli/reg/2023/988
