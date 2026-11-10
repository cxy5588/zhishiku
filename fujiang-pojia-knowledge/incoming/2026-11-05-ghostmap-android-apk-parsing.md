---
title: GhostMap: malformed APK resources trap Android in persistent boot loop
cve: 无（Bitdefender 研究，未编 CVE）
severity: high
cvss: 
epss: 
epss_date: 
entry_type: vuln
source_grade: A
kev: false
product: Android 10-17 (system_server / APK 解析)
versions: Android 10 至 17
vendor_original: 
cpe_clues: 
ports: 
keywords: 
status: candidate
impact: high
impact_reason: 
source_verified: false
verified: false
repro_tested: false
first_seen: 2026-11-10
source_published: 
last_verified: 
aliases: []
sources: https://www.bitdefender.com/en-us/blog/hotforsecurity/google-reopens-ghostmap-investigation
suggested_category: mobile-rev
---

## 指纹

- 待核实：按参考链接确认受影响产品与版本区间、暴露端口/特征。CPE 只是线索，不要直接当最终结论；以厂商原文为准。

## 前置条件

- 待核实：目标版本在区间内；见 NVD/CVE 描述与厂商公告。

## PoC（探测）

- 待核实：本条为公告级自动采集，未收录可验证 PoC；不要直接当利用步骤用，先按参考链接核实。

## 利用步骤

- 待核实。

## 修复与缓解

- 按厂商公告升级到修复版本；无法升级时按厂商临时缓解措施处理。

## 描述（原文摘要）

Bitdefender 2026-11-05 披露：APK 内 ZIP 条目的压缩方法与声明未压缩大小被两个 Android 库解读不一致，8,408 字节 APK 被映射约 16MB，读越界触发 SIGBUS，system_server 反复崩溃，手机无法完成开机，安全模式也无效，恢复需恢复出厂设置（丢数据）。演示 APK 无可执行代码、不请求权限、不需打开。只造成崩溃，不执行代码、不窃数据、不提权。Google 最初称超出安全更新范围，后重开调查并升为 High，暂无补丁、无 CVE。

## 逐源观察

- Bitdefender Labs 2026-11-05; Google 重开并升 High; 无 CVE

## 参考

- https://www.bitdefender.com/en-us/blog/hotforsecurity/google-reopens-ghostmap-investigation | https://www.helpnetsecurity.com/2026/11/05/ghostmap-android-bug-research/
