# 跨平台安装与使用

macOS、Windows 和 Linux 使用同一个安装包，要求 Python 3.11 或更高版本。Windows 直接运行 Python 和 PowerShell，无需 WSL、Git Bash 或管理员终端。

## 安装

从 Release 下载 `brand-takedown-v1.4.3.zip`，解压后进入 `brand-takedown` 目录。也可以克隆仓库。

macOS 和 Linux：

```bash
python3 --version
python3 -m pip install --require-hashes -r requirements.txt
python3 scripts/doctor.py
```

Windows PowerShell：

```powershell
py -3 --version
py -3 -m pip install --require-hashes -r requirements.txt
py -3 scripts/doctor.py
```

Windows 会安装 `tzdata`，用于处理 IANA 时区和夏令时。macOS 和 Linux 使用系统时区数据，通常没有额外依赖。若 Linux 精简环境缺少时区数据库，先安装系统的 `tzdata` 包，再运行检查。

`doctor.py` 返回 `"ok": true` 后即可使用。它会检查 TLS、时区、文件锁、中文读写和目录权限。也可以检查已经存在的数据目录：

```powershell
py -3 scripts/doctor.py --data-dir "$HOME/.gemini/brand-protection"
```

## Windows 建档与取证

以下路径均在当前用户目录中。JSON 中的 Windows 路径建议写成 `C:/Users/name/evidence/photo.png`，省去反斜杠转义。

```powershell
$work = Join-Path $HOME '.gemini/brand-protection'
$brand = Join-Path $work 'example-brand'
New-Item -ItemType Directory -Force $brand | Out-Null
Copy-Item examples/sample-profile.json (Join-Path $brand 'input.json')
$env:BRAND_TAKEDOWN_REGISTRY = Join-Path $work 'registry.json'

# 编辑 input.json 后运行。
py -3 scripts/brand_registry.py validate --profile-file "$brand/input.json"
py -3 scripts/brand_registry.py init --slug example-brand --data-dir $brand --profile-file "$brand/input.json"

$result = py -3 scripts/case_manager.py create --slug example-brand --url 'https://suspect.example/product' --types COPYRIGHT_CLONE | ConvertFrom-Json
$caseDir = $result.case_dir
py -3 scripts/recon_target.py run --slug example-brand --case-dir $caseDir --url 'https://suspect.example/product'
py -3 scripts/recon_target.py add-evidence --slug example-brand --case-dir $caseDir --url 'https://suspect.example/product' --source "$HOME/Pictures/证据 截图.png"
py -3 scripts/recon_target.py refresh-manifest --slug example-brand --case-dir $caseDir
py -3 scripts/case_manager.py summary --slug example-brand
```

PowerShell 用 `$env:NAME = 'value'` 设置环境变量，用反引号换行。README 中的 bash 示例使用 `export NAME=value` 和反斜杠换行；Windows 执行时应改用对应语法，或把命令写成一行。

投诉材料、补件、反通知、下线复核和雷达归档的参数在三种系统上一致。参见 [案件跟进流程](followup-workflows.md)。Agent 应使用检测到的 Python 解释器，以参数数组调用脚本，不应在 Windows 上拼接 bash 命令。

## 文件与图片

把品牌数据保存在本机硬盘，使用当前用户有写入权限的目录。Windows 建议使用 NTFS。目录名和文件名支持中文和空格；文件路径作为单独参数传入。

macOS、Linux 使用 `0700/0600` 权限；Windows 使用私有访问控制列表，授予当前用户、SYSTEM 和本机管理员访问权限。Windows 路径检查会拒绝网络盘、设备名、备用数据流和目录联接点。OneDrive 重解析目录应换成普通本地目录。

三个系统都支持 PNG 和 BMP 图片比对。macOS 还可调用系统的 `sips` 转换 JPG 等格式；Windows 和 Linux 上先把这类图片转为 PNG 或 BMP。

三个系统均先写临时文件、刷新文件内容，再替换目标文件。Windows 遇到短暂的文件占用会重试，持续占用时保留旧文件并报错；目录 `fsync` 仅在 macOS 和 Linux 上执行。

## 开发验证

Windows 使用 `py -3`，macOS 和 Linux 使用 `python3` 执行下面的脚本。以下以已加入 PATH 的 `python` 为例：

```text
python scripts/verify_source.py
python scripts/check_distribution.py --smoke
python -m unittest discover -s tests -v
python scripts/check_distribution.py --package
```

CI 在 Ubuntu 24.04、macOS 15 和 Windows Server 2022 上，分别使用 Python 3.11、3.13 测试源码和解压后的安装包。Windows 专用的目录联接、只读文件和大小写路径测试，只在 Windows 上执行。

## 实现依据

- [Python Windows 文件锁](https://docs.python.org/3.11/library/msvcrt.html)
- [Python IANA 时区数据](https://docs.python.org/3.11/library/zoneinfo.html#data-sources)
- [Windows 文件名和路径规则](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
- [Windows 文件权限接口](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
