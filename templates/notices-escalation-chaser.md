# 第三阶段升级模板集：超时严正催办函 (`Tier-2 Chaser`) 与上游/监管越级投诉函 (`Tier-3 Escalation`)

---

## 模板 3A：`Tier-2` 超时未处置严正催办暨避风港豁免丧失警示函 (`SLA Breach Chaser`)

**Trigger**: `ENFORCEMENT_SLA` 通道超过 `sla_hours` 且 `check_liveness.py` 确认站点仍处于存活侵权状态。
**Subject**: `[FINAL ESCALATION NOTICE — TICKET {{TICKET_REF}}] Unresolved Infringement & Loss of Safe Harbor Immunity — {{TARGET_DOMAIN}}`

```text
URGENT COMPLIANCE ESCALATION — PRIOR NOTICE UNRESOLVED

- Original Notice Submitted (UTC): {{SUBMITTED_AT_UTC}}
- Prior Ticket / Reference Number: {{TICKET_REF}}
- Target Infringing Domain / URLs: {{TARGET_URLS_LIST}}
- Fresh Liveness Verification Timestamp (UTC): {{LATEST_PROBE_UTC}} (Status: STILL LIVE at {{DIRECT_DNS_IPS}})

Dear Legal and Compliance Leadership at {{PROVIDER_NAME}},

On {{SUBMITTED_AT_UTC}}, {{LEGAL_ENTITY_NAME_EN}} served your organization with a formal, statutorily compliant takedown and abuse notice (Reference: {{TICKET_REF}}) regarding active counterfeit sales, trademark/copyright infringement, and consumer fraud operating at {{TARGET_DOMAIN}}.

Automated forensic verification conducted at {{LATEST_PROBE_UTC}} confirms that the unlawful content remains publicly accessible through your infrastructure.

NOTICE OF ACTUAL KNOWLEDGE & LOSS OF SAFE HARBOR IMMUNITY
Please be advised that statutory Safe Harbor liability exemptions — including 17 U.S.C. § 512(c)(1)(A)(iii) under the U.S. DMCA and Article 6 of EU Regulation (EU) 2022/2065 (Digital Services Act) — strictly condition immunity upon the service provider acting EXPEDITIOUSLY to remove or disable access to unlawful material upon obtaining actual knowledge.

Having received our complete notice and documentary proof on {{SUBMITTED_AT_UTC}}, {{PROVIDER_NAME}} now possesses indisputable actual knowledge of ongoing counterfeiting and consumer fraud. Continued provision of services to {{TARGET_DOMAIN}} exposes your organization to contributory infringement claims and product-liability risk:
{{PRODUCT_SAFETY_HAZARD_PARAGRAPH}}

FINAL 48-HOUR REMEDIATION WINDOW
Unless access to {{TARGET_DOMAIN}} is disabled within forty-eight (48) hours of this notice, we will escalate this matter without further notice to upstream infrastructure/regulatory authorities (including ICANN Contractual Compliance, the TLD Registry, upstream BGP transit providers, and relevant EU Digital Services Coordinators) and preserve this correspondence as evidence of willful inaction.

Sincerely,

/s/ {{SIGNATORY_NAME}}
{{SIGNATORY_NAME}}, {{SIGNATORY_TITLE}}
{{LEGAL_ENTITY_NAME_EN}} ({{SIGNATORY_EMAIL}})
```

---

## 模板 3B：`Tier-3` 向 `ICANN Contractual Compliance` 及顶级域注册局 (`Registry`) 投诉注册商违约报告

**Portal**: https://www.icann.org/compliance/complaint (DNS Abuse / Registrar 2013 RAA § 3.18 Non-Compliance) & Corresponding TLD Registry Abuse Contact.
**Subject**: `[RAA § 3.18 NON-COMPLIANCE & DNS ABUSE] Failure by Registrar {{REGISTRAR_NAME}} (IANA {{REGISTRAR_IANA_ID}}) to Mitigate Active Phishing/Fraud Domain {{TARGET_DOMAIN}}`

```text
Dear ICANN Contractual Compliance / TLD Registry Abuse Team,

{{LEGAL_ENTITY_NAME_EN}} (brand owner of "{{BRAND_NAME}}", official domain https://{{PRIMARY_OFFICIAL_DOMAIN}}/) submits this formal compliance complaint regarding the failure of ICANN-accredited registrar {{REGISTRAR_NAME}} (IANA ID: {{REGISTRAR_IANA_ID}}) to investigate and mitigate substantiated DNS Abuse (brand-impersonation phishing and fraudulent e-commerce scam) pursuant to Section 3.18 of the 2013 Registrar Accreditation Agreement (RAA) and the 2024 ICANN DNS Abuse Amendments.

1. CHRONOLOGY OF REGISTRAR INACTION
- Abusive Domain: {{TARGET_DOMAIN}}
- Tier-1 Substantiated Abuse Report Sent to {{REGISTRAR_ABUSE_EMAIL}}: {{SUBMITTED_AT_UTC}} (Ticket: {{TICKET_REF}})
- Tier-2 Escalation Follow-Up Sent: {{TIER2_ESCALATED_AT_UTC}}
- Current Verification ({{LATEST_PROBE_UTC}}): Domain remains active without `clientHold` mitigation ({{DIRECT_DNS_IPS}}).

2. EVIDENCE OF DNS ABUSE (PHISHING & DECEPTIVE IMPERSONATION)
{{TARGET_DOMAIN}} impersonates {{LEGAL_ENTITY_NAME_EN}} to deceive consumers into submitting payment card credentials and funds for non-existent or hazardous counterfeit merchandise (see attached Tier-1 & Tier-2 notices, screenshots, and SHA-256 forensic manifest).

3. REQUESTED COMPLIANCE ACTION
We request that ICANN Contractual Compliance require {{REGISTRAR_NAME}} to fulfill its RAA § 3.18 obligations immediately, and we request that the TLD Registry Operator exercise its registry-level authority to place {{TARGET_DOMAIN}} on `serverHold` to prevent ongoing harm to the public.

Submitted by:
{{SIGNATORY_NAME}}, {{SIGNATORY_TITLE}}
{{LEGAL_ENTITY_NAME_EN}} | {{ENTITY_ADDRESS}} | {{SIGNATORY_EMAIL}}
```

---

## 模板 3C：`Tier-3` 向欧盟成员国数字服务协调官 (`Digital Services Coordinator - DSC`) 投诉托管商违反 `DSA Art. 16`

**Subject**: `[ARTICLE 53 DSA COMPLAINT] Hosting Provider {{PROVIDER_NAME}} Failure to Act on Substantiated Article 16 Illegal Content Notice — {{TARGET_DOMAIN}}`

```text
To the Competent Digital Services Coordinator (pursuant to Article 53 of Regulation (EU) 2022/2065),

{{LEGAL_ENTITY_NAME_EN}} lodges this formal complaint under Article 53 of Regulation (EU) 2022/2065 (Digital Services Act) against intermediary hosting provider {{PROVIDER_NAME}} for systemic failure to comply with Articles 16 and 17 of the DSA.

1. SUMMARY OF NON-COMPLIANCE
- Intermediary Service Provider: {{PROVIDER_NAME}} ({{TARGET_ENDPOINT}})
- Reported Illegal Content URL(s): {{TARGET_URLS_LIST}}
- Date of Formal Article 16 Notice: {{SUBMITTED_AT_UTC}} (Ticket Reference: {{TICKET_REF}})
- Date of Chaser Escalation: {{TIER2_ESCALATED_AT_UTC}}

Despite receiving a complete, substantiated Article 16 notice documenting EU trademark/design infringement and uncertified hazardous counterfeit products violating Regulation (EU) 2023/988 (GPSR), {{PROVIDER_NAME}} has failed to process the notice diligently, failed to disable access expeditiously, and/or failed to provide a compliant Statement of Reasons under Article 17 DSA.

All prior notices, timestamps, and cryptographic forensic captures are attached. We request supervisory intervention pursuant to Chapter IV of Regulation (EU) 2022/2065.

Respectfully,
/s/ {{SIGNATORY_NAME}}
{{SIGNATORY_NAME}}, {{SIGNATORY_TITLE}} — {{LEGAL_ENTITY_NAME_EN}} ({{SIGNATORY_EMAIL}})
```
