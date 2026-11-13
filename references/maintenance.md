# 仓库维护

## 公共后缀规则

扫描使用随包附带的规则。`Public suffix update check` 工作流每周检查上游提交，在 Actions 摘要中显示结果，不直接替换运行规则。

```bash
python3 scripts/update_psl.py check
```

更新时使用完整的上游提交 SHA。先预览来源、摘要和规则数量：

```bash
python3 scripts/update_psl.py update --commit "$UPSTREAM_COMMIT"
```

确认后保存当前规则摘要，并指定仓库外的备份目录：

```bash
CURRENT_SHA256=$(python3 -c 'import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("references/public_suffix_list.dat.gz").read_bytes()).hexdigest())')
python3 scripts/update_psl.py update --commit "$UPSTREAM_COMMIT" --apply \
  --expected-current "$CURRENT_SHA256" --cache-dir "$HOME/.cache/brand-takedown/psl"
```

脚本核对上游 Git blob，检查规则结构，并将提交号、原始 SHA-256 和规则数量写入快照。替换前保存原文件和源码清单；更新中断时可以恢复：

```bash
python3 scripts/update_psl.py recover --cache-dir "$HOME/.cache/brand-takedown/psl"
```

回退时，`--to` 使用更新结果中的 `previous_sha256`，`--expected-current` 使用当前快照摘要：

```bash
python3 scripts/update_psl.py rollback --to "$PREVIOUS_SHA256" \
  --expected-current "$CURRENT_SHA256" --cache-dir "$HOME/.cache/brand-takedown/psl"
```

更新和回退都会同步源码清单。随后运行源码测试、构建安装包，再解压重跑测试。将通过验证的修改提交到仓库。

离线更新支持 `--source-file` 和 `--blob-sha`，后者必须来自选定上游提交的文件记录。规则来源见 [Public Suffix List](https://publicsuffix.org/list/)，许可见 [public-suffix-license.md](public-suffix-license.md)。

## 主分支保护

[branch-protection.json](../.github/branch-protection.json) 定义四组必需检查，并关闭强推和分支删除。仓库管理员可以在有 `Administration: write` 权限的环境中应用：

```bash
gh api --method PUT repos/zlxmygit/brand-takedown/branches/main/protection \
  --input .github/branch-protection.json
```

配置文件提交到仓库不代表设置已经生效。应用后读取同一接口，确认四组检查、管理员约束和删除限制。此操作使用管理员已有的认证环境，不将凭证写入仓库。
