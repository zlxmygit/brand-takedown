# 海关进出口双向拦截与高危产品安全降维打击指南 (Customs & Product Safety)

> [!IMPORTANT]
> 本模块对应的所有官方申报通道在 `case.json` 中必须登记为 `channel_class = "REGULATORY_FILING"`（监管备案与执法情报通道），仅记录回执与案件号，**严禁对其触发针对商业服务商的 48h/72h 避风港催办警告**。

---

## 一、 源头制造国 + 欧美目的港“双向海关锁死”体系

跨境假冒硬件/大件产品 90% 以上通过海运整柜、散货拼箱或海外仓专线流转。同时布控 **源头出口海关** 与 **欧美目的港进口海关** 可直接物理扣押假货并销毁：

### 1. 美国海关与边境保护局 (`U.S. CBP`)
- **通道 A：已有美国 USPTO 下证商标或美国版权登记 —— `CBP e-Recordation` 正式备案**
  - 入口：https://iprr.cbp.gov/
  - 费用与效力：每个商标类别官费约 190 USD，备案后全美所有海陆空口岸海关官员系统内自动共享正品鉴别指南（Product ID Guide），发现未在 `Authorized Importers` 白名单内的货主直接扣留（Detention）与没收（Seizure）。
- **通道 B：无论是否已完成海关备案均可立即提交 —— `CBP e-Allegations` 在线贸易违规密报**
  - 入口：https://eallegations.cbp.gov/Home/Index
  - 适用场景：当通过假站退货地址、测试买样面单、提单数据库（ImportYeti / Panjiva）锁定假货海外仓地址、进口商名称或低报货值逃税线索时，直接在线提交知识产权侵权与商业欺诈举报（支持附上传商标/专利证书及假站截图）。

### 2. 加拿大边境服务局 (`CBSA`)
- **通道**：`Request for Assistance (RFA)` 知识产权边境援助申请
- **入口**：https://www.cbsa-asfc.gc.ca/security-securite/ipr-dpi/menu-eng.html
- **特点**：无需官费（需承担实际扣货后的仓储处置担保），有效期 2 年可续期，覆盖加拿大注册商标与版权。

### 3. 欧盟 27 国海关统一布控 (`EUIPO IP Enforcement Portal — IPEP`)
- **通道**：通过欧盟知识产权局门户提交单份 **Union Application for Action (`AFA`)**，依据 `Regulation (EU) No 608/2013` 同步激活欧盟全部 27 个成员国海关拦截！
- **入口**：https://www.euipo.europa.eu/en/enforce-ip/ip-enforcement-portal
- **支持权利类型**：欧盟注册商标（`EUTM`）及 **欧盟注册共同体外观设计（`RCD`）**！即使造假分子不在车体/包装贴牌（白牌进口到欧洲再贴标），只要外观落入 `RCD` 六视图保护范围，鹿特丹港、汉堡港、安特卫普港等重点大件清关港均可依法直接查扣！

### 4. 英国皇家税务与海关总署 (`HMRC / UK Border Force`)
- **通道**：英国脱欧后欧盟 AFA 不再覆盖英国口岸，需凭英国 `UKIPO` 注册商标或外观专利独立在线提交 **UK Application for Action (`AFA`)**。
- **入口**：https://www.gov.uk/guidance/apply-for-action-to-protect-your-intellectual-property-rights

### 5. 源头出口拦截：中国海关总署知识产权保护系统 (`GACC`)
- **适用条件**：品牌拥有中国大陆注册商标证书（`CNIPA`）或中国外观/发明专利证书。
- **入口**：http://202.127.48.145:8888/ （中国国际贸易单一窗口 / 海关总署知识产权备案系统）
- **战略价值**：免费备案！备案后仅将品牌方自有工厂与授权供应链列为合法使用人（白名单），任何未经授权的造假工厂在深圳盐田/蛇口、宁波、上海、青岛等口岸报关出口含该商标货物时，在离港前即被中国海关直接扣留查处。

---

## 二、 高功率锂电与高危品类“产品安全合规”降维打击 (Product Safety Nuclear Option)

当品牌档案 `profile.json` 中 `product_risk_profile.category` 属于高风险管控品类（如 `high_power_lithium_mobility` 高速锂电越野车/电动滑板车/E-Bike、`electronics_battery`、`children_or_medical`）时，自动激活以下监管通报与平台连带责任施压：

### 1. 向商业平台（Shopify / Stripe / PayPal / 主机商）附加的产品安全连带风险警示
假冒高功率锂电载具普遍使用劣质无保护板电芯、无认证充电器及劣质制动车架，缺失：
- **北美强制/行业核心标准**：`UL 2849`（电驱动系统电气安全）、`UL 2271`（轻型电动车锂电池安全）、`16 CFR Part 1512 / CPSC` 安全规范、`49 CFR / UN38.3` 危险品锂电运输测试、美国 `DOT / EPA` 合规。
- **欧洲强制法规**：**欧盟《通用产品安全条例》(GPSR, `Regulation (EU) 2023/988`)**（强制要求所有向欧盟消费者远程销售的产品必须在页面披露真实的欧盟境内责任人 `EU Responsible Person` 名称、邮政地址与电子联系方式，假冒站 100% 缺失或盗用伪造！）、`Machinery Directive 2006/42/EC`、`CE` 认证。
- **施压效果**：在投诉信中严正声明——平台/支付机构在已被权利人书面告知该商户正在销售未经 `UL / CE / GPSR` 认证的假冒大功率锂电池高速载具后，若继续为其提供建站交易或资金结算便利，一旦发生锂电池爆燃火灾或骑行重伤亡事故，权利人与受害消费者将依法追究服务商的重大过失与产品责任连带赔偿！

### 2. 官方产品安全监管机构备案通报
- **美国消费品安全委员会 (`U.S. CPSC`)**：通过 https://www.saferproducts.gov/ 以正品制造商身份通报市场上流窜假冒危险品及涉案欺诈域名，防止假货起火事故被误算在正品品牌头上并推动监管联合封杀。
- **欧盟危险产品快速预警系统 (`EU Safety Gate` / 原 RAPEX)**：结合 `GPSR Article 22` 向目标成员国市场监管局（Market Surveillance Authorities）通报在线销售的无欧盟责任人、无 CE 认证的假冒高危锂电车辆链接，监管局有权直接责令托管商与域名注册商屏蔽欧盟访问。
- **官网防伪公示联动**：建议品牌主站在固定路径（如 `/pages/counterfeit-warning`）维护实时更新的《官方授权渠道与假冒欺诈网站黑名单声明》，在所有向海关、CPSC、Safe Browsing、支付商与注册商提交的申诉中引用该官方公示 URL 作为最高权重自证锚点。
