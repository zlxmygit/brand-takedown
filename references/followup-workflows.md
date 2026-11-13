# 补件、反通知与下线复核

## 补件

服务商要求补件时，先记录 `NEED_MORE_INFO` 和工单号，再准备新材料。在请求 JSON 中设置 `submission_kind: "SUPPLEMENT"`。其余证据、权利和联系人字段沿用普通材料格式。

```bash
python3 scripts/case_manager.py update-channel --slug example-brand --case-dir "$CASE_DIR" \
  --channel-id host --status NEED_MORE_INFO --ticket-ref "$TICKET_REF"
python3 scripts/packets.py --slug example-brand --case-dir "$CASE_DIR" \
  prepare --request-file "$SUPPLEMENT_JSON"
```

材料会绑定当前工单和本次补件要求。审批、EML 导出和 `submit` 的用法不变。补件保留首次提交时间与升级轮次；商业通道从本次发送时间重新计算本轮跟进时限。监管通道只记录补件，不计算商业催办时限。每次收到新的补件要求，重新登记 `NEED_MORE_INFO`。

`submission_kind` 支持 `INITIAL`（首次提交）、`SUPPLEMENT`（补件）、`ESCALATION`（升级）和 `COUNTER_NOTICE_RESPONSE`（反通知回应）。省略时，系统按通道状态选择普通提交类型；反通知回应必须明确指定。

## 反通知

登记反通知后，只暂停对应通道。系统保存剩余跟进时间，撤销尚未发送的升级计划，并将未结事项列入 `LEGAL_REVIEW`。同案其他通道可以继续处理。

暂停期间，普通材料的生成、审批、导出和回执登记都会停止。回应反通知时，在请求 JSON 中增加以下字段，继续引用具体证据：

```json
{
  "submission_kind": "COUNTER_NOTICE_RESPONSE",
  "legal_task_id": "实际 task_id",
  "response_source_ref": "反通知登记时的 source_ref",
  "response_reviewed_by": "回应审核人",
  "response_text": "审核后的回应正文"
}
```

这些字段补充到现有请求中，不能单独替代完整请求。回应使用独立正文和回执记录，不改变升级轮次，也不关闭法律待办。

对应通道的全部反通知都经 `resolve-legal` 处理后，普通流程恢复。系统按暂停时剩余的时长计算下一次跟进时间。暂停前的材料须重新生成并审批。

## 下线复核与恢复告警

工单状态与网站状态分开管理。确认下线时，用 `review-liveness` 记录审核人、来源和证据。

先将截图或复核记录通过 `add-evidence` 导入。随后准备 `review-evidence.json`：

```json
{
  "evidence": [
    {"capture_id": "实际 CAP 标识", "filename": "review.txt"}
  ]
}
```

证据应覆盖全部目标 URL。案件包含关联域名时，可以在人工导入的复核文档引用中增加 `observed_urls`，列出文档实际检查的完整 URL。原始抓取页面不能凭此扩展到其他网址。

```bash
python3 scripts/case_manager.py review-liveness --slug example-brand --case-dir "$CASE_DIR" \
  --decision DOWN --reviewer "审核人" --source-ref "$REVIEW_SOURCE" \
  --summary "已复核全部目标网址" --evidence-file "$REVIEW_EVIDENCE_JSON"
```

确认后进入观察期。临时断网或解析失败保留原复核结果；再次发现页面内容时，系统保存恢复告警，直到人工复核。新增目标或关联域名需要重新检查范围。

复核确认恢复访问后，用同一命令提交 `--decision ACTIVE` 和对应证据。系统归档原告警，恢复正常案件状态。未结反通知继续保留。

## 雷达归档

用以下命令归档已处理记录，每次最多 1,000 条：

```bash
python3 scripts/ct_radar.py --slug example-brand --archive-reviewed \
  --reviewer "审核人" --archive-limit 1000
```

仅归档已有审核人和处理理由的记录，待审核记录留在活动队列。归档数据保存在品牌目录下的 `radar-archive.sqlite3`。返回值包含批次 ID、记录数和摘要。

归档先提交数据库，再清理活动文件。中途退出后，下次扫描或归档会继续清理已提交的副本。已归档域名保留去重索引，不会因再次命中 CT 查询而自动回到待审核队列。

```bash
# 导出一个归档批次
python3 scripts/ct_radar.py --slug example-brand --export-batch "$BATCH_ID" > "$ARCHIVE_JSON"

# 发现新情况后，明确恢复该域名的审核
python3 scripts/ct_radar.py --slug example-brand --restore-domain "suspect.example" \
  --reviewer "审核人" --rationale "发现新的页面内容，重新核实"
```

恢复审核保留原归档记录。备份品牌目录时，一并备份 `radar_seen.json` 和 `radar-archive.sqlite3`。
