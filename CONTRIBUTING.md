# 贡献指南

运行时代码使用 Python 3.11 或更高版本的标准库。测试使用合成品牌和 `.example` 域名，网络测试连接本机 HTTP 服务。

## 修改代码

为修改的行为补充正常路径和异常路径测试。涉及案件隔离、证据校验或审批时，测试应验证实际结果。新增配置字段时，同步更新 Schema、校验器和示例。

外部工具接入需要核对接口、授权和重复执行行为，并补充集成测试。法律参考附上原始来源、适用地区和服务商角色。CI 中的第三方 Action 固定到审核过的提交。

## 修改文档

中文文档参考 [zh-tech-writing](https://github.com/leter/zh-tech-writing)。先说明功能和使用方法，直接写动作、命令和结果。配置要求放在对应步骤，避免在各节重复说明。

修改前通读全文，修改后核对命令、链接和中英文排版。发布说明只列本次更新，详细操作留在 README 或参考文档。

## 提交前检查

```bash
python3 -m compileall -q scripts tests
python3 scripts/doctor.py
python3 scripts/brand_registry.py validate --profile-file examples/sample-profile.json
python3 -m unittest discover -s tests -v
python3 scripts/package_skill.py --out /tmp/brand-takedown.zip
```

检查提交文件，确认只包含源码、文档和合成测试数据。真实品牌档案、证书、案件和邮件保存在仓库外。
