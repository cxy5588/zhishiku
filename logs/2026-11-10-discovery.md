# 2026-11-10 新源发现（首跑）

- 源清单：`sources.yaml` v1 已建，Tier A 7 个 API、Tier B 20+ 厂商 PSIRT、Tier C 15+ 研究者第一手、Tier D 中文源+聚合，全部纳入采集。
- 今日采集：脚本实测 50 条入库（NVD 43 + CISA KEV 7），critical 23 条，0 错误。产品字段初版用 CPE 失败 43 条，已用 CVE.org API 补齐 43/43。
- 新源发现：首跑以整合已确认源为主，未新增 sources.yaml 之外的源；每日任务起每天按 SOURCES_DISCOVERY.md 跑 4 组搜索+社交搜索+反查，发现核实过的再加。
- 待办：Cisco openVuln API 需申请 key，未配前用 RSS/公告页人工核查。
