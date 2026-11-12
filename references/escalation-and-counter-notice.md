# 三阶加压升级与恶意反通知反制手册 (Escalation & Counter-Notice SOP)

## 一、 零容忍三阶升级路径 (`Escalation Ladder`)

严禁在服务商超时未响应时机械重发第一封相同邮件（会被工单系统归并为低优先级）。按 `case_manager.py` 的 `escalation_tier` 执行逐级加压：

### Tier 1 → Tier 2：超时严正催办函 (`SLA Breach Chaser`)
- **触发条件**：`ENFORCEMENT_SLA` 通道超过预设 `sla_hours`（48h / 72h / 120h），且 `check_liveness.py` 探测目标仍处于存活侵权状态。
- **核心施压点**：
  1. 置顶列出首次通知发送时间（UTC）、原工单号（`ticket_ref`）及刚刚采集的最新存活证据时间戳与截图哈希；
  2. **避风港豁免丧失警告 (`Loss of Safe Harbor Immunity`)**：明确指出根据 `17 U.S.C. § 512(c)(1)(A)(iii)` 及 `EU Regulation (EU) 2022/2065 (DSA) Article 6`，托管/技术服务商仅在“知悉侵权或非法活动后迅速采取移除或断开访问措施（acts expeditiously to remove or to disable access）”的前提下才享有免责保护。无视合格法定通知已构成实际知情（Actual Knowledge），继续提供服务将直接触发共同侵权（Contributory Infringement）责任；
  3. 设定最后通牒窗口（`48 hours`），逾期未处置将立即上报上级监管与上游基础设施机构。

### Tier 2 → Tier 3：越级向上游与监管机构投诉 (`Upstream & Regulatory Escalation`)
当直接服务商在 Tier 2 最后通牒到期后依然不作为（例如抗投诉二道贩子注册商或离岸 VPS 代理商）：

1. **域名注册商失职 → 直报 `ICANN Contractual Compliance` + 顶级域注册局 (`Registry`)**
   - **法理依据**：所有 ICANN 认证注册商均受《2013 注册商委任协议》（`2013 RAA § 3.18.1`）及 2024 DNS Abuse 修正案强制约束，必须调查并合理处置钓鱼（Phishing）、恶意欺诈与非法滥用报告，并在网站显著披露有效 Abuse 联系方式且保存处置记录。
   - **ICANN 官方投诉入口**：https://www.icann.org/compliance/complaint （选择 `DNS Abuse / Registrar Abuse Contact Failure`，附上 Tier 1 与 Tier 2 发给注册商的原始邮件及超时未处理记录 —— 注册商极度忌惮 ICANN 合规调查警告！）。
   - **顶级域注册局 (`Registry`) 同步上报**：
     - `.com` / `.net` (Verisign)：https://www.verisign.com/en_US/domain-names/online-brand-protection/index.xhtml
     - `.shop` (GMO Registry)：`abuse@gmo.jp` / https://www.gmoregistry.com/en/contact/
     - `.store` / `.online` / `.site` / `.tech` (Radix Registry)：https://radix.website/report-abuse/
     - `.xyz` / `.top` / `.vip` / `.club`：各自注册局 DNS Abuse 紧急冻结入口（请求下发最高权限 `serverHold`）。
   - **`EU NIS2 Directive Article 28` 拒绝披露升级**：若注册商或顶级域注册局无正当理由拒绝在 72 小时内向合法知识产权权利人披露隐藏在隐私保护后的真实注册人身份数据，依据 `Directive (EU) 2022/2555 (NIS2) Article 28(5)` 向该注册商所在欧盟成员国的 NIS2 主管机关（Competent Authority）及 ICANN RDS/WHOIS Disclosure 合规通道提起正式投诉。

2. **离岸/代理 VPS 主机商装死 → 穿透 `BGP ASN` 直报上游机房与一级带宽商 (`Upstream Transit / Data Center`)**
   - 执行 `whois <direct_dns_ip>` 查询该 IP 所属的 `ASN`、上游机房（如 Cogent、Arelion/Telia、Lumen、Hurricane Electric、Equinix、Leaseweb）及 RIR（`ARIN` / `RIPE NCC` / `APNIC`）登记的 `OrgAbuseEmail`，向其上游网络提供商举报下游客户托管钓鱼与假冒危险品欺诈站点。

3. **面向欧盟市场的服务商违规 → 直报欧盟成员国数字服务协调官 (`Digital Services Coordinator - DSC`)**
   - 依据 `EU DSA Article 53`，向该服务商主营业地（如爱尔兰 Coimisiún na Meán、德国 Bundesnetzagentur、荷兰 ACM、法国 Arcom）投诉其违反 `DSA Article 16 & 17` 拒绝处理非法假冒商品通知且未出具法定裁决书。

4. **核心品牌近似抢注域名顽抗 → 启动域名强制夺回程序 (`URS` vs `UDRP`)**
   - **快速低成本冻结：`URS (Uniform Rapid Suspension)`**（适用于 `.shop`、`.store`、`.online`、`.xyz` 等新通用顶级域 nTLDs，官费仅约 375–500 USD，由 Forum / MFSD 在 2–3 周内裁定将侵权域名强制锁定暂停直至到期）。
   - **永久过户夺回：`UDRP (Uniform Domain-Name Dispute-Resolution Policy)`**（适用于 `.com` 等所有 gTLDs，如 `brandsports.com`、`brandusa.com`、`thebrand.com` 等混淆抢注域名）：
     - 仲裁机构：**WIPO Arbitration and Mediation Center** 或 **Forum (NAF)**（可将同一团伙名下多个假冒域名合并为单一件 **Consolidated UDRP Complaint** 一案打包审理，大幅平摊官费！合并立案依据：相同建站模板、相同 `GA / Meta Pixel`、相同注册商/注册日期簇、相同产品盗图）。
     - 法定三要件证明包（由本 Skill `evidence/` 目录直接提供）：① 争议域名与权利人注册商标相同或混淆性近似；② 被投诉人对争议域名不享有任何合法权益；③ 域名系恶意注册并恶意使用（克隆官网售假构成铁证）。裁决胜诉后直接将域名过户到品牌方名下并 301 重定向回正品官网！

---

## 二、 `DMCA Counter-Notice`（恶意反通知）10 个工作日复活死线反制 SOP

> [!CAUTION]
> 根据 `17 U.S.C. § 512(g)(2)(C)`，若侵权者向 Shopify / 主机商 / Google 提交了形式上完整的 `Counter-Notice`，服务商转发给权利人后，若权利人未在 **10–14 个工作日** 内通知服务商已向法院提起禁令诉讼，服务商可能恢复侵权链接！因此 `Gmail` 巡检一旦捕获 `Counter-Notice` 必须立即执行以下 **非诉讼极速反制二连击**：

### 反制第 1 击：揭穿虚假伪证反通知 (`Defective & Perjurious Counter-Notice Rejection`)
根据 `17 U.S.C. § 512(g)(3)`，合法的 `Counter-Notice` 必须包含侵权者的**真实法定姓名、真实物理居住/营业地址、真实电话**，且非美国居民必须签署声明**同意接受服务商所在地美国联邦地区法院管辖并接受诉讼文书送达**。
- **核验动作**：立即核查对方反通知上填写的姓名与地址（跨境造假团伙 95% 填写不存在的假美国门牌号、免税州虚拟信箱、与己无关的第三方民宅或货代仓库地址）。
- **回击文书**：在 24 小时内向平台法务团队正式回函（附 Google Street View / USPS 地址不存在或系无关场所截图），指出该 `Counter-Notice` 系违反 `17 U.S.C. § 512(g)(3)(D)` 的伪证虚假陈述（`Facially Invalid & Perjurious Counter-Notice`），在法律上自始无效（`null and void`），平台无义务且不得依据无效伪证文件恢复欺诈店铺，并应依据平台 ToS 直接永久封禁该欺诈账户！

### 反制第 2 击：换轨至无自动恢复机制的硬核权利通道 (`Non-DMCA Hard Lock`)
`10–14` 个工作日恢复条款**仅适用于纯版权 `DMCA` 通知，完全不适用于注册商标售假、外观设计专利侵权与支付/商业欺诈**！
- 立即向同一平台同步补交：**① 注册商标假冒侵权投诉（附 USPTO / EUIPO / UKIPO 注册证书 PDF）** + **② 外观设计专利侵权投诉（附证书与六视图）** + **③ 支付通道 Stripe/PayPal 售假冻资投诉**。即使 DMCA 工单到期，店铺与收款通道已被商标与反欺诈规则永久焊死，彻底断绝复活可能！
