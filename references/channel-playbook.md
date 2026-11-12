# 全渠道立体打击作战手册 (Channel Strike Playbook)

执行申诉时，必须严格遵守 **防打草惊蛇三梯队打击顺序**，避免提前触发源站 `Geo-IP / Ad-Cloaking` 斗篷或证据销毁。

---

## 第一梯队 (`T+0` 断金流、封店铺、挂红屏 —— 不向源站泄露权利人信息)

### 1. 支付通道与收单行 (Payment Processors & Acquirers — SLA: `48h`)
- **取证要素**：从 `recon-report.json` 或匿名 `Checkout` 探测获取 `Stripe pk_live_*`、`PayPal Merchant ID / Client ID`、信用卡收单 iframe 域名或隐藏收单壳站（`B 站`）。
- **官方入口**：
  - **Stripe**：发信至 `heretohelp@stripe.com` 及 `legal@stripe.com`（主题注明 `URGENT: Counterfeit Fraud & Brand Impersonation - Merchant pk_live_...`），同步提交 https://stripe.com/legal/ssa 违规举报。
  - **PayPal**：发信至 `infringementreport@paypal.com` 与 `aupviolations@paypal.com`（援引 PayPal Acceptable Use Policy 售假与欺诈条款）。
  - **Airwallex / Adyen / Klarna / Afterpay**：分别投递 `compliance@airwallex.com`、`compliance@adyen.com`、`ip@klarna.com`。
  - **卡组织收单行封锁**：若完成测试买样（Test Purchase）获取账单描述符（Billing Descriptor）与收单行（Acquirer BIN），通过 **IACC RogueBlock** 或 Visa/Mastercard Global Brand Protection 通道冻结商户号。

### 2. 建站 SaaS 平台源头封店 (E-Commerce SaaS — SLA: `48h`)
- **Shopify**（重点核查 `shopify_domain` 即原始 `.myshopify.com` 及 `shopify_shop_id`）：
  - 版权盗图/扒文案：https://www.shopify.com/legal/reports/copyright
  - 商标侵权/假冒商品：https://www.shopify.com/legal/reports/trademark
  - 欺诈不发货/克隆钓鱼（违反 AUP）：https://www.shopify.com/legal/reports/acceptable-use
- **Shoplazza（店匠）**：发信至 `legal@shoplazza.com` / `abuse@shoplazza.com`
- **Shopline**：发信至 `legal@shoplineapp.com` / `abuse@shopline.com`
- **BigCommerce / Wix / Squarespace**：
  - BigCommerce: https://www.bigcommerce.com/dmca/ (`copyright@bigcommerce.com`)
  - Wix: https://www.wix.com/about/abuse (`abuse@wix.com`)

### 3. 反钓鱼与浏览器安全红屏拉黑 (Anti-Phishing & Safe Browsing — SLA: `48h`)
适用于 **1:1 冒充官网骗取消费者信用卡/个人信息** 的克隆站及 **虚假物流追踪配套站**：
- **Google Safe Browsing**：https://safebrowsing.google.com/safebrowsing/report_phish/
- **Microsoft Defender SmartScreen**：https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest
- **Netcraft Anti-Phishing**（全球多家浏览器与防火墙上游数据源）：https://report.netcraft.com/report
- **APWG (Anti-Phishing Working Group)**：发信至 `reportphishing@apwg.org`
- **Cloudflare Radar Domain Categorization**：请求重分类为 `Phishing / Scam`

### 4. 搜索引擎与广告投流截流 (Search & Ad Networks — SLA: `120h`)
- **Google Search DMCA 移除**：https://reportcontent.google.com/forms/dmca_search
- **Google Ads / Shopping 商标与假货举报**：https://support.google.com/ads/troubleshooter/4578507
- **Bing Copyright / Counterfeit Removal**：https://www.microsoft.com/en-us/concern/bing
- **Meta (Facebook / Instagram) Brand Rights Protection**：https://www.facebook.com/help/contact/trademarkform （先在 https://www.facebook.com/ads/library/ 检索品牌词抓拍在投广告 ID）
- **TikTok IP Protection Portal**：https://ippc.tiktok.com/

---

## 第二梯队 (本地固证与第一梯队投递后 —— 拔域名解析、断发信、穿 CDN 端源站)

> [!IMPORTANT]
> 进入第二梯队前，先执行 `python3 <SKILL_DIR>/scripts/recon_target.py archive-wayback --slug <slug> --url "<target_url>"` 留存公开第三方快照。

### 5. 域名注册商 `ClientHold` 暂停解析与真实注册人披露 (Registrar — SLA: `72h`)
- **关键策略**：纯民事商标争议注册商通常会推脱让你去打 `UDRP`；但针对 **克隆官网钓鱼（Phishing）、预付款诈骗（Advance-Fee Scam）、虚假物流配套站（Fraud Infrastructure）及危及人身安全的假冒高功率产品**，依据 **ICANN 2013 RAA § 3.18**，注册商有义务核查滥用并直接下发 EPP `clientHold` 停止解析！
- **常见注册商直达通道**：
  - **Namecheap**：`abuse@namecheap.com` / 工单入口 https://support.namecheap.com/
  - **GoDaddy**：`abuse@godaddy.com` / https://supportcenter.godaddy.com/AbuseReport
  - **Tucows / OpenSRS / Hover**：`compliance@tucows.com`
  - **NameSilo**：`abuse@namesilo.com`
  - **Dynadot**：`abuse@dynadot.com`
  - **Alibaba Cloud / HiChina (万网)**：`domainabuse@service.aliyun.com`
  - **Gname**：`complaint@gname.com`
  - **Porkbun**：`abuse@porkbun.com`
- **同步附加请求**：若注册商位于欧盟或服务欧盟市场，同信附带 **EU NIS2 Directive Article 28 域名注册数据合法披露请求**，索取隐藏在隐私保护壳后的真实注册人姓名、邮箱、电话与账单地址。

### 6. 邮箱发信服务商封禁 (ESP / MX Providers — SLA: `72h`)
根据 `dns.json` 中的 `MX` 与 `TXT (SPF)` 记录精准投递：
- Google Workspace：`abuse@google.com`
- Microsoft 365 / Outlook：`abuse@messaging.microsoft.com`
- Zoho Mail：`abuse@zohocorp.com`
- SendGrid：`abuse@sendgrid.com`
- Mailgun：`abuse@mailgun.com`
- Klaviyo：`abuse@klaviyo.com`

### 7. 反向代理 CDN 与源站主机商 (CDN & Hosting — SLA: `72h`)
- **Cloudflare 穿透策略**：Cloudflare 并非源站主机，但通过 https://abuse.cloudflare.com 提交 `Trademark / Copyright / Phishing` 报告时，勾选请求披露源站托管商（Origin Hosting Provider）并转发通知；拿到 Cloudflare 回复披露的真实源站主机商及 Abuse 邮箱后，立即在 `case.json` 新增 `origin_host` 通道直击源站机房！
- **主流欧洲主机商（必须使用 `EU DSA Art. 16` 模板）**：Hetzner (`abuse@hetzner.com` / https://abuse.hetzner.com)、OVHcloud (https://www.ovh.com/abuse/)、Hostinger (`abuse@hostinger.com`)、Leaseweb (`abuse@leaseweb.com`)。
- **主流北美主机商（使用 `US DMCA + Lanham Act` 模板）**：DigitalOcean、Vultr、Linode/Akamai、AWS (`trustandsafety@support.aws.com` / https://support.aws.amazon.com/#/contacts/report-abuse)。

### 8. 虚假物流追踪配套站专项打击 (Fake Logistics / Scam Enabler Sites)
针对类似 `brand-track.com` 不直接挂购物车但用于伪造物流轨迹欺骗消费者与发卡行的配套域名：
- **侵权类型标记**：`PHISHING_OR_FAKE_TRACKING` + `TRADEMARK_IMPERSONATION`。
- **主攻方向**：注册商 `Registrar Phishing/Fraud Abuse`（强调其属于电信网络诈骗与信用卡拒付欺诈基础设施，要求 24h 内 `ClientHold`）+ Google Safe Browsing / Netcraft 红屏拦截。
