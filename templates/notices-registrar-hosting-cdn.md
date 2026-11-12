# 第二梯队申诉模板集：域名注册商 `ClientHold` + `NIS2` 披露、北美 DMCA 及欧盟 `DSA Art. 16` 托管/CDN 申诉

---

## 模板 2A：域名注册商紧急暂停解析 (`clientHold`) 暨 `EU NIS2 Art. 28` 真实注册人信息披露申请函

**Recipient**: `{{REGISTRAR_ABUSE_EMAIL}}` (从 `whois.abuse_emails` 提取)
**Subject**: `[DNS ABUSE / PHISHING & COUNTERFEIT FRAUD] Request for Immediate clientHold Suspension & Registrant Disclosure — {{TARGET_DOMAIN}}`

```text
Dear Abuse and Compliance Team at {{REGISTRAR_NAME}} (IANA ID: {{REGISTRAR_IANA_ID}}),

We represent {{LEGAL_ENTITY_NAME_EN}}, owner of the "{{BRAND_NAME}}" brand and registered trademarks (Official Website: https://{{PRIMARY_OFFICIAL_DOMAIN}}/).

Pursuant to Section 3.18 of the 2013 ICANN Registrar Accreditation Agreement (RAA) and the ICANN DNS Abuse Amendments, we report active phishing, deceptive brand impersonation, and commercial counterfeit fraud operating on the domain name registered through your service:

- Abusive Domain Name: {{TARGET_DOMAIN}}
- Infringing / Fraudulent URLs: {{TARGET_URLS_LIST}}
- Current Name Servers & Direct IPs: {{NAMESERVERS_LIST}} / {{DIRECT_DNS_IPS}}
- Forensic Evidence Timestamp (UTC) & SHA-256 Hash: {{CAPTURED_AT_UTC}} ({{RAW_HTML_SHA256}})

1. GROUNDS FOR IMMEDIATE DNS SUSPENSION (EPP clientHold)
This is NOT a mere good-faith civil naming dispute. The registrant registered "{{TARGET_DOMAIN}}" specifically to impersonate our official domain (https://{{PRIMARY_OFFICIAL_DOMAIN}}/), deceive consumers into believing they are transacting with {{LEGAL_ENTITY_NAME_EN}}, harvest payment credentials/funds under false pretenses, and distribute uncertified counterfeit products (or operate fabricated parcel-tracking scam infrastructure).
{{PRODUCT_SAFETY_HAZARD_PARAGRAPH}}

2. INTELLECTUAL PROPERTY CREDENTIALS (ATTACHED)
{{TRADEMARKS_BULLET_LIST}}
{{PATENTS_BULLET_LIST}}

3. FORMAL REQUEST FOR REGISTRANT DATA DISCLOSURE (ICANN RAA & EU NIS2 DIRECTIVE ARTICLE 28)
Because the registrant's WHOIS details are currently redacted behind privacy/proxy services while engaging in commercial fraud targeting North American and European consumers, we formally request disclosure of the underlying registrant's verified name, organization, physical address, email address, telephone, and billing contact record pursuant to ICANN RAA § 3.7.7.3, GDPR Art. 6(1)(f) legitimate legal enforcement interest, and Article 28 of Directive (EU) 2022/2555 (NIS2 Directive). We undertake to use disclosed data strictly for legal enforcement, UDRP/court proceedings, and law-enforcement referrals.

4. REQUESTED ACTIONS WITHIN 72 HOURS
(a) Place {{TARGET_DOMAIN}} on EPP `clientHold` status immediately to halt ongoing consumer fraud;
(b) Disclose the underlying registrant identity records to {{SIGNATORY_EMAIL}}; and
(c) Provide your abuse ticket reference number for our tracking records.

DECLARATION
I have a good faith belief that the activities conducted via {{TARGET_DOMAIN}} are unauthorized, unlawful, and abusive. I declare under penalty of perjury that the foregoing information is accurate and complete, and that I am authorized to act on behalf of {{LEGAL_ENTITY_NAME_EN}}.

Sincerely,

/s/ {{SIGNATORY_NAME}}
{{SIGNATORY_NAME}}, {{SIGNATORY_TITLE}}
{{LEGAL_ENTITY_NAME_EN}}
Address: {{ENTITY_ADDRESS}}
Email: {{SIGNATORY_EMAIL}}
Phone: {{SIGNATORY_PHONE}}
```

---

## 模板 2B：北美托管主机商 / CDN 法定下架通知 (`17 U.S.C. § 512 DMCA` + `15 U.S.C. § 1114 / § 1125(a)`)

> **法理分流硬护栏 (`COPYRIGHT_CLONE` 校验)**：仅当案件 `infringement_types` 包含 `COPYRIGHT_CLONE` 时保留 `17 U.S.C. § 512` 标题引用与下方 `Section 1`；若案件未盗用版权素材（仅冒用商标售假或经营钓鱼/虚假物流站），渲染时**必须移除 `17 U.S.C. § 512 DMCA` 引用与 `Section 1`**，仅保留 Lanham Act 商标假货与平台 ToS 欺诈条款！

**Applicable To**: US/Canadian Hosting Providers, Reverse-Proxy CDNs (Cloudflare Abuse Portal + Origin Host Disclosure Request).
**Subject**: `Statutory DMCA Takedown (17 U.S.C. § 512) & Trademark Counterfeit Notice — {{TARGET_DOMAIN}} ({{DIRECT_DNS_IPS}})`

```text
Dear Designated Copyright Agent and Abuse Team,

Pursuant to the Digital Millennium Copyright Act, 17 U.S.C. § 512(c)(3), and the Lanham Act, 15 U.S.C. §§ 1114 and 1125(a), {{LEGAL_ENTITY_NAME_EN}} hereby demands the expeditious removal or disabling of access to infringing content hosted or proxied on your network at:

- Infringing Domain & IP(s): {{TARGET_DOMAIN}} ({{DIRECT_DNS_IPS}})
- Exact Infringing URLs:
{{TARGET_URLS_LIST}}

1. IDENTIFICATION OF COPYRIGHTED WORKS INFRINGED (17 U.S.C. § 512(c)(3)(A)(ii))
Original product photographs, graphic layouts, and textual descriptions owned exclusively by {{LEGAL_ENTITY_NAME_EN}}, published first at:
{{COPYRIGHT_ORIGINALS_LIST}}

2. TRADEMARK COUNTERFEITING & UNFAIR COMPETITION (15 U.S.C. §§ 1114, 1125(a))
In addition to wholesale copyright theft, the operator unlawfully displays our "{{BRAND_NAME}}" marks to market unauthorized counterfeit goods:
{{TRADEMARKS_BULLET_LIST}}
{{PRODUCT_SAFETY_HAZARD_PARAGRAPH}}

3. REQUEST FOR ORIGIN HOST DISCLOSURE (IF ACTING AS REVERSE PROXY / CDN)
If your network acts as a reverse proxy/CDN for {{TARGET_DOMAIN}}, please immediately disclose the identity and abuse contact email of the upstream origin hosting provider and forward this statutory notice without delay.

4. MANDATORY STATUTORY STATEMENTS
- I have a good faith belief that use of the material in the manner complained of is not authorized by the copyright/trademark owner, its agent, or the law.
- I swear, under penalty of perjury, that the information in this notification is accurate, and that I am the owner, or authorized to act on behalf of the owner, of an exclusive right that is allegedly infringed.

Electronic Signature: /s/ {{SIGNATORY_NAME}}
Name & Title: {{SIGNATORY_NAME}}, {{SIGNATORY_TITLE}}
Rights Owner: {{LEGAL_ENTITY_NAME_EN}}
Mailing Address: {{ENTITY_ADDRESS}}
Email: {{SIGNATORY_EMAIL}}
Telephone: {{SIGNATORY_PHONE}}
```

---

## 模板 2C：欧盟及英国托管服务商强制非法内容通知 (`EU Digital Services Act Regulation (EU) 2022/2065 Article 16` + `EUTMR` + `RCD` + `GPSR`)

**Applicable To**: EU/EEA/UK Hosting Providers (Hetzner, OVHcloud, Hostinger, Leaseweb, etc.) & Any Storefront Targeting EU/UK Consumers.
**Subject**: `[FORMAL NOTICE — EU DSA ARTICLE 16] Illegal Counterfeit Content, EUTM/RCD Infringement & GPSR Safety Violation — {{TARGET_DOMAIN}}`

```text
To the Designated Point of Contact pursuant to Article 12 & Article 16 of Regulation (EU) 2022/2065 (Digital Services Act),

{{LEGAL_ENTITY_NAME_EN}} submits this formal Notice of Illegal Content under Article 16 of Regulation (EU) 2022/2065 (DSA) and Regulation 19 of the UK Electronic Commerce Regulations 2002 regarding illegal counterfeit offerings hosted on your infrastructure:

1. EXACT ELECTRONIC LOCATION OF ILLEGAL CONTENT (DSA Art. 16(2)(b))
- Hosted Domain & Server IP(s): https://{{TARGET_DOMAIN}}/ ({{DIRECT_DNS_IPS}})
- Specific Illegal URLs:
{{TARGET_URLS_LIST}}

2. SUBSTANTIATED EXPLANATION OF ILLEGALITY UNDER EU & MEMBER STATE LAW (DSA Art. 16(2)(a))
The reported URLs offer unauthorized counterfeit replicas targeting European consumers in direct violation of:
(a) EU Trade Mark Regulation (Regulation (EU) 2017/1001, Article 9) & UK Trade Marks Act 1994 s. 10:
{{TRADEMARKS_BULLET_LIST}}
(b) Registered Community Design Regulation (Council Regulation (EC) No 6/2002, Article 19 — where applicable, design certificates and 6-view drawings attached):
{{PATENTS_BULLET_LIST}}
(c) EU General Product Safety Regulation (GPSR, Regulation (EU) 2023/988): The operator markets uncertified counterfeit goods into the Union without disclosing a valid EU Responsible Person (Article 16 GPSR) and without mandatory CE / safety compliance:
{{PRODUCT_SAFETY_HAZARD_PARAGRAPH}}
(d) Fraudulent Impersonation & GDPR Controller Misrepresentation: The website omits lawful Impressum / Data Controller disclosures while impersonating {{LEGAL_ENTITY_NAME_EN}}.

3. SUBMITTER IDENTIFICATION (DSA Art. 16(2)(c))
- Legal Entity: {{LEGAL_ENTITY_NAME_EN}}
- Authorized Representative: {{SIGNATORY_NAME}}, {{SIGNATORY_TITLE}}
- Registered Address: {{ENTITY_ADDRESS}}
- Official Contact Email: {{SIGNATORY_EMAIL}}

4. BONA FIDE ACCURACY DECLARATION (DSA Art. 16(2)(d))
I hereby confirm my bona fide belief that the information and allegations contained in this notice are accurate and complete pursuant to Article 16(2)(d) of Regulation (EU) 2022/2065, and I declare under penalty of perjury that I am authorized to act on behalf of {{LEGAL_ENTITY_NAME_EN}}.

Pursuant to Article 16(5) and Article 17 of the Digital Services Act, please confirm receipt without undue delay, disable access to the illegal content expeditiously (noting loss of hosting liability exemption under Article 6 DSA upon actual knowledge), and provide your reasoned decision.

Signed: /s/ {{SIGNATORY_NAME}}
{{SIGNATORY_NAME}}, {{SIGNATORY_TITLE}} — {{LEGAL_ENTITY_NAME_EN}}
```
