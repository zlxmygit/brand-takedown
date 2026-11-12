# 第一梯队申诉模板集：支付冻资、建站 SaaS 封店、钓鱼红屏与假物流站 (Payment, SaaS & Anti-Phishing Notices)

> **渲染规则**：生成具体案件 `packets/` 文书时，必须使用 `profile.json` 与 `recon-report.json` 中的真实字段替换所有 `{{...}}` 变量（其中 `{{OFFICIAL_PRODUCT_URLS}}` 优先映射自 `profile.official_product_urls`，未配置时回退填入 `https://{{PRIMARY_OFFICIAL_DOMAIN}}/`）；若某可选段落（如高危锂电产品安全声明或外观设计专利）在当前品牌档案中存在，则完整保留并填入真实编号；若当前品牌无该项资产，则整段裁剪删除，严禁残留空占位符。

---

## 模板 1A：支付通道紧急售假与欺诈冻资申诉函 (`Stripe / PayPal / Acquirers`)

**Recommended Recipients**:
- Stripe: `heretohelp@stripe.com`, `legal@stripe.com`
- PayPal: `infringementreport@paypal.com`, `aupviolations@paypal.com`

**Subject**: `[URGENT FRAUD & COUNTERFEIT ALERT] Unauthorized Brand Impersonation & Counterfeit Sales — {{TARGET_DOMAIN}} ({{PAYMENT_IDENTIFIER}})`

```text
Dear Risk, Compliance, and Legal Enforcement Team,

We write on behalf of {{LEGAL_ENTITY_NAME_EN}}, the exclusive owner of the "{{BRAND_NAME}}" brand and associated intellectual property rights (Official Website: https://{{PRIMARY_OFFICIAL_DOMAIN}}/).

We have identified an unlawful counterfeit and brand-impersonation storefront operating at:
- Infringing Storefront URL(s): {{TARGET_URLS_LIST}}
- Linked Checkout / Payment Cloak Domain (if applicable): {{CLOAK_B_SITE_DOMAIN}}
- Identified Payment Merchant / Publishable Key Identifier: {{PAYMENT_IDENTIFIER}}
- Forensic Evidence Snapshot Timestamp (UTC): {{CAPTURED_AT_UTC}} (SHA-256 Manifest Verified)

1. SUMMARY OF ACCEPTABLE USE POLICY (AUP) & INTELLECTUAL PROPERTY VIOLATIONS
The operator of {{TARGET_DOMAIN}} is willfully impersonating {{BRAND_NAME}} and utilizing your payment processing infrastructure to collect consumer funds for unauthorized, counterfeit products (or non-delivery advance-fee fraud). The merchant has no affiliation, license, or authorization from {{LEGAL_ENTITY_NAME_EN}}.

2. INTELLECTUAL PROPERTY OWNERSHIP
- Registered Trademarks:
{{TRADEMARKS_BULLET_LIST}}
- Registered Design / Utility Patents (where applicable):
{{PATENTS_BULLET_LIST}}
- Official Authentic Product Reference: {{OFFICIAL_PRODUCT_URLS}}
- Official Public Counterfeit Alert Page: {{COUNTERFEIT_WARNING_URL}}

3. SEVERE CONSUMER HARM, CHARGEBACK EXPOSURE & PRODUCT SAFETY LIABILITY
{{PRODUCT_SAFETY_HAZARD_PARAGRAPH}}
Consumers deceived by {{TARGET_DOMAIN}} inevitably suffer financial loss or receive uncertified, hazardous counterfeit goods, creating immediate chargeback spikes, card-network compliance violations (Visa/Mastercard Brand Protection rules), and severe regulatory exposure.

4. REQUESTED IMMEDIATE ACTION
We respectfully demand that your Risk and Compliance team immediately:
(a) Suspend payment processing for the merchant account(s) associated with {{TARGET_DOMAIN}} and identifier {{PAYMENT_IDENTIFIER}};
(b) Freeze illicit proceeds held in reserve to cover inevitable consumer chargebacks and statutory restitution; and
(c) Confirm account termination to our legal contact below.

STATUTORY DECLARATIONS
I have a good faith belief that the disputed use of our intellectual property and brand identity described above is not authorized by the rights owner, its agent, or the law. I swear, under penalty of perjury, that the information in this notification is accurate and that I am authorized to act on behalf of {{LEGAL_ENTITY_NAME_EN}}.

Respectfully submitted,

/s/ {{SIGNATORY_NAME}}
{{SIGNATORY_NAME}}, {{SIGNATORY_TITLE}}
{{LEGAL_ENTITY_NAME_EN}}
Address: {{ENTITY_ADDRESS}}
Email: {{SIGNATORY_EMAIL}}
Phone: {{SIGNATORY_PHONE}}
```

---

## 模板 1B：建站 SaaS 平台全店封停申诉包 (`Shopify / Shoplazza / Shopline`)

**Shopify Portal Fast-Fill Checklist**（供门户粘贴或 `browser` 子代理预填）：
- **Trademark Portal**: https://www.shopify.com/legal/reports/trademark
- **Copyright (DMCA) Portal**: https://www.shopify.com/legal/reports/copyright
- **Acceptable Use (Fraud/Impersonation)**: https://www.shopify.com/legal/reports/acceptable-use
- **Underlying Store Identifier**: `{{SHOPIFY_DOMAIN}}` (Shop ID: `{{SHOPIFY_SHOP_ID}}`)

> **法理分流硬护栏 (`COPYRIGHT_CLONE` 校验)**：仅当案件 `infringement_types` 包含 `COPYRIGHT_CLONE`（确有盗用官网原创图片/视频/文案）时，保留下方标题中的 `Copyright Infringement (DMCA)` 与 `PART II — DMCA COPYRIGHT TAKEDOWN NOTICE`；若案件仅为商标冒用/售假且未盗图，渲染时**必须整段移除 `PART II` 及 DMCA 字样**！

**Email / Narrative Body**:

```text
Dear Trust & Safety and IP Legal Team,

{{LEGAL_ENTITY_NAME_EN}} ("{{BRAND_NAME}}", official website https://{{PRIMARY_OFFICIAL_DOMAIN}}/) submits this formal notice of Trademark Infringement, Counterfeit Goods Sales, Copyright Infringement (DMCA), and Acceptable Use Policy (Deceptive Brand Impersonation) violations against the storefront hosted on your platform:

- Custom Domain: https://{{TARGET_DOMAIN}}/
- Underlying Platform Store Identifier: {{SHOPIFY_DOMAIN}} (Shop ID: {{SHOPIFY_SHOP_ID}})
- Specific Infringing URLs:
{{TARGET_URLS_LIST}}

PART I — TRADEMARK INFRINGEMENT & COUNTERFEIT GOODS (15 U.S.C. § 1114 / § 1125(a) & EU/UK Trademark Law)
The reported store unlawfully uses our "{{BRAND_NAME}}" trademark in its domain/listings to market counterfeit replicas of our flagship products without authorization:
{{TRADEMARKS_BULLET_LIST}}
{{PATENTS_BULLET_LIST}}

PART II — DMCA COPYRIGHT TAKEDOWN NOTICE (17 U.S.C. § 512(c)(3))
The store has copied our original copyrighted product photography, audiovisual media, and marketing text directly from our official website:
- Original Copyrighted Work URL(s):
{{COPYRIGHT_ORIGINALS_LIST}}
- Infringing Copied URL(s):
{{TARGET_URLS_LIST}}

PART III — DECEPTIVE IMPERSONATION & PUBLIC SAFETY RISK
{{PRODUCT_SAFETY_HAZARD_PARAGRAPH}}

STATUTORY STATEMENTS
1. I have a good faith belief that use of the copyrighted materials and trademarks in the manner complained of is not authorized by the rights owner, its agent, or the law.
2. I swear, under penalty of perjury, that the information in this notification is accurate, and that I am the intellectual property owner or am authorized to act on behalf of {{LEGAL_ENTITY_NAME_EN}}.

Please terminate the entire fraudulent storefront ({{SHOPIFY_DOMAIN}} / {{TARGET_DOMAIN}}) expeditiously.

Signed: /s/ {{SIGNATORY_NAME}}
Name & Title: {{SIGNATORY_NAME}}, {{SIGNATORY_TITLE}}
Company: {{LEGAL_ENTITY_NAME_EN}}
Address: {{ENTITY_ADDRESS}}
Official Email: {{SIGNATORY_EMAIL}}
Phone: {{SIGNATORY_PHONE}}
```

---

## 模板 1C：反钓鱼浏览器红屏拉黑与虚假物流配套站举报说明 (`Google Safe Browsing / SmartScreen / Netcraft / APWG`)

**Portals**:
- Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/
- Microsoft SmartScreen: https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest
- Netcraft: https://report.netcraft.com/report
- APWG Email: `reportphishing@apwg.org`

**Submission Technical Brief (Copy-Paste Ready)**:

```text
PHISHING, BRAND IMPERSONATION & E-COMMERCE SCAM REPORT

- Malicious / Deceptive URL: https://{{TARGET_DOMAIN}}/
- Impersonated Legitimate Brand & Official Site: {{BRAND_NAME}} (https://{{PRIMARY_OFFICIAL_DOMAIN}}/)
- Official Brand Fraud Alert Reference: {{COUNTERFEIT_WARNING_URL}}
- Resolved IP(s): {{DIRECT_DNS_IPS}} | Registrar: {{REGISTRAR_NAME}}

THREAT CLASSIFICATION:
[1] Brand Impersonation / Credential & Payment Card Harvesting: {{TARGET_DOMAIN}} fraudulently mimics the official {{BRAND_NAME}} webstore (or operates as a fabricated shipment-tracking portal linked to counterfeit scam orders) to deceive North American and European consumers into submitting payment card details and personally identifiable information.
[2] Advance-Fee / Fake Tracking Scam Enabler (for fake logistics domains): Where operated as a bogus parcel tracker, the domain generates fabricated transit updates to stall consumer credit-card chargeback disputes past bank deadlines.

Please classify https://{{TARGET_DOMAIN}}/ as Deceptive / Phishing / Fraud across Safe Browsing and threat intelligence feeds immediately.
Reported by Authorized Brand Owner: {{LEGAL_ENTITY_NAME_EN}} ({{SIGNATORY_EMAIL}}).
```
