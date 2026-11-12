# 多法域法理路由矩阵与防驳回指南 (Legal Jurisdictions & Routing Matrix)

## 1. 铁律：严禁混淆版权 (`DMCA`)、商标 (`Trademark`) 与假货欺诈 (`Counterfeit/Phishing`)

| 侵权表现特征 | 适用核心法理 | 严禁踩坑事项 |
| :--- | :--- | :--- |
| **直接盗用官网原创产品实拍图、宣传视频、详情页文案、扒取前端 HTML/CSS 代码** | **版权侵权 (Copyright Infringement)**<br>- 北美：`17 U.S.C. § 512(c)/(d)` (DMCA)<br>- 加拿大：`Copyright Act Notice-and-Notice`<br>- 欧盟：`InfoSoc Directive 2001/29/EC` + `DSA Art. 16`<br>- 英国：`CDPA 1988` | **无需商标下证即可立即发起**！核心必填项是提供我方官网首发原始作品 URL（`official_source_url`）与侵权页盗图 URL 的一一对照及伪证罪声明（`under penalty of perjury`）。 |
| **域名含品牌词、页面冒用品牌名称/LOGO、销售非正品授权的假货（即使对方自己重拍了图片或换了背景）** | **商标侵权与假冒商品 (Trademark & Counterfeit)**<br>- 美国（已注册）：`Lanham Act § 32 (15 U.S.C. § 1114)`<br>- 美国（未下证/申请中/使用在先）：`Lanham Act § 43(a) (15 U.S.C. § 1125(a))` 虚假原产地标识与不正当竞争<br>- 加拿大：`Trademarks Act s. 7(b) Passing Off` & `s. 20`<br>- 欧盟：`EUTMR Regulation (EU) 2017/1001 Art. 9` + `DSA Art. 16`<br>- 英国：`Trade Marks Act 1994 s. 10`<br>- 澳大利亚：`Trade Marks Act 1995 s. 120` & `Australian Consumer Law s. 18` | **严禁在纯商标/假货但未盗图的案件中套用纯 DMCA 模板**，否则 Shopify / Google / 主机商法务会以“DMCA 不涵盖商标争议”直接驳回！若同时盗图且冒用商标，必须分列 **Part I: Copyright (DMCA)** 与 **Part II: Trademark & Counterfeit** 双重主张。 |
| **抄袭产品工业造型（即使抹掉 LOGO 改换别的牌子售卖同款模具假车/假产品）** | **外观设计专利 / 注册共同体外观设计**<br>- 欧盟：`Registered Community Design (RCD) Regulation (EC) No 6/2002 Art. 19`<br>- 英国：`UK Registered Designs Act 1949`<br>- 美国：`35 U.S.C. § 271 & § 289` (US Design Patent) | 随函必须附上外观设计专利证书 PDF 及 **产品六视图（6-View Drawings）与侵权商品角度对比图**。 |
| **1:1 克隆官网外观、盗用我方公司名称/地址、骗取买家付款不发货或诱导填写信用卡** | **网络钓鱼、商业身份盗用与电信欺诈**<br>- 全球注册商：`ICANN 2013 RAA § 3.18` Abuse 强制处置条款<br>- 欧盟：`GDPR` 控制者虚假披露 + 企业身份盗用 (`Corporate Identity Theft`) | 不受民事知识产权抗辩拖延限制，直接定性为危害公共网络安全的欺诈基础设施，要求立即断网暂停。 |

---

## 2. 按服务商所在地与目标市场的法域自动切换规则

### A. 北美市场与美国服务商 (`US` / `CA`)
- **适用对象**：Shopify（加拿大/美国实体）、Cloudflare、Namecheap、GoDaddy、Stripe US、PayPal、DigitalOcean、AWS 等。
- **法定必需要素 (`17 U.S.C. § 512(c)(3)` 法定 6 要素，缺一不可)**：
  1. 被侵犯版权作品的明确标识及官网原始 URL；
  2. 侵权材料在目标网站上的精确 URL（不能只写根域名，克隆整站需写明根域名 + 代表性侵权商品页 URL 列表）；
  3. 投诉方完整联系信息（权利人实体英文全称、注册地址、官方企业邮箱、电话）；
  4. **善意信念声明 (Good Faith Statement)**：`I have a good faith belief that use of the material in the manner complained of is not authorized by the copyright owner, its agent, or the law.`
  5. **准确性与伪证罪授权声明 (Accuracy & Perjury Statement)**：`I swear, under penalty of perjury, that the information in this notification is accurate, and that I am the copyright/intellectual property owner or am authorized to act on behalf of the owner of an exclusive right that is allegedly infringed.`
  6. 授权代表物理或电子签名（`/s/ <Authorized Signatory Name>`）。

### B. 欧洲市场与欧盟/欧洲服务商 (`EU` / `EEA` / `UK`)
- **适用对象**：Hetzner（德国）、OVHcloud（法国）、Hostinger（立陶宛/塞浦路斯）、Leaseweb（荷兰）、Klarna（瑞典）以及任何向欧盟消费者展示欧元定价或支持欧盟配送的站点。
- **核心武器 —— 欧盟《数字服务法案》(Digital Services Act, `Regulation (EU) 2022/2065`, `Article 16`)**：
  - 欧洲主机商对美国 DMCA 并无法定义务，但对 **EU DSA Article 16 非法内容通知（Notice and Action Mechanism）** 负有法定审查、及时移除与出具书面裁决理由（Statement of Reasons, Art. 17）的强制义务！
  - **DSA Article 16 必填四要素**：
    1. 充分阐述为何该信息构成欧盟法或成员国法下的非法内容（`Illegal Content`：销售侵犯欧盟注册商标 `EUTMR`、欧盟注册外观设计 `RCD` 的假冒商品，以及违反欧盟《通用产品安全条例》`Regulation (EU) 2023/988` 的无证危险产品与欺诈行为）；
    2. 侵权内容的精确电子位置（精确 URL 清单）；
    3. 提交人的姓名/实体名称及电子邮箱；
    4. **DSA 诚信准确声明**：`I hereby confirm my bona fide belief that the information and allegations contained in this notice are accurate and complete pursuant to Article 16(2)(d) of Regulation (EU) 2022/2065 (Digital Services Act).`
- **英国 (`UK`)**：脱欧后独立援引 `UK Trade Marks Act 1994 s. 10`、`Electronic Commerce (EC Directive) Regulations 2002 Regulation 19`（知悉非法活动后丧失托管免责）及 `UK Registered Designs`。
