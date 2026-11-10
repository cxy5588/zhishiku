---
name: kb-mobile-rev
description: CVE/PoC 知识库 · APK / Android 逆向：反编译、Manifest 导出组件、WebView、硬编码密钥、Frida Hook、证书固定绕过、加固脱壳。公开资料整理，verified=false。
verified: false
sources: 公开资料整理（Android 安全公告 / OWASP MASVS / 研究者分析 / 厂商公告；出处见各条参考）
---

# APK / Android 逆向（0 条，2026-11-10 新建，等每日采集补）
> 条目为公开资料整理（出处见文末「参考」），`利用步骤` 属待验证假设；出报告前按目标版本自验并把 `verified` 置为 true。

收录范围：Android 应用漏洞（有 CVE 或无 CVE 都收，无 CVE 按 YYYY-MM-DD-应用-类型.md），以及逆向新知识：新工具、新脱壳/反混淆手法、新检测绕过。
每条必须写清：应用名 + 包名 + 版本 + 证据（反编译代码片段 / Manifest / Frida 脚本 / 抓包），只凭“某 App 有漏洞”一句话不收。

## 存储边界（2026-11-10 用户定）
- 只记：应用名、包名、版本、SHA256、证据位置（Manifest/反编译片段所在类/方法）、来源链接。
- 不要提交：原始 APK 样本、完整反编译输出、敏感数据（密钥、Token、个人数据、凭证）。
- 条目类型：`entry_type=vuln`（已确认漏洞卡）与 `entry_type=method`（逆向方法/工具卡）分开，方法卡不要写成已确认漏洞。
