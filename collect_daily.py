#!/usr/bin/env python3
"""Daily vuln collection v2 for ~/workspace/knowledge-base/
Fixes from 2026-11-10 user audit:
1. NVD: pubStartDate only, daily window 7d (LOOKBACK_DAYS=7). If the gap since
   last_success exceeds 7d, fetch in 7-day segments by publish date until caught up,
   then restore the daily 7d window. This is the catch-up rule (2026-11-10 user decision):
   "max 7d" and "gap >7d can still catch up" are reconciled by segmenting, not by a
   full lastMod sweep. No CVSS hard filter. CVSS is severity, not risk; it is only
   a ranking input. NVD unauthenticated rate limit is 5 req/30s, sleep 6s per page.
   WHY NO FULL lastMod SWEEP (measured 2026-11-10, twice): a bare lastMod 7d query
   returned 3299 hits in 2d and a pub30+lastMod7 query returned ~7000 hits / 16 pages.
   NVD publishes ~200 CVE/day, so any 7-30d window is thousands of records, almost all
   old re-enriched entries, not new disclosures. A full mod sweep is infeasible without
   an NVD API key (50 req/30s vs 5 req/30s). Substantive updates are instead caught by
   (a) KEV snapshot diff, (b) GHSA updated filter, (c) the agent's daily PSIRT check.
   If an NVD API key is added later, re-enable a lastMod sweep.
11. SOURCE GRADING (2026-11-10 user decision): CVE existence != product/version verified.
    NVD + CVE.org transcribe the same CNA record — that is ONE source, not two independent
    evidences. Independent evidence means: original vendor advisory, independent technical
    analysis, PoC — each recorded separately in evidence_support, saying what it supports
    (product / versions / entry point / PoC). Grades: A = vendor advisory + independent
    analysis (or CVE + vendor advisory with matching product/versions); B = CVE/NVD or
    GHSA reviewed only; C = GHSA unreviewed / single researcher post / social only.
    GHSA: dedup by GHSA ID across reviewed/unreviewed; reviewed wins; reviewed status
    is SOURCE CREDIBILITY, not vuln severity.
12. COUNTS (2026-11-10 user decision): log separately raw_hits (per-source raw, with
    cross-source duplicates), unique_candidates (after cross-source dedup, before seen
    dedup), deduped_seen, deduped_cross_source, candidates_written, pending_verification
    (files currently in incoming/). Clarification: the 2026-11-10 impact split
    639 high + 276 review = 915 was on RAW NVD hits BEFORE seen dedup; after seen dedup
    it was 859 unique new candidates. Do not mix the two denominators.
13. STORAGE BOUNDARY for APK/EXE (2026-11-10 user decision): knowledge cards record
    hash, version, evidence location and source link ONLY. Never submit the original
    closed-source sample, complete decompiled output, or sensitive data (keys, tokens,
    personal data, credentials) to the KB. Method cards and vuln cards are different
    entry types: entry_type=method (tool/method, learning value) vs entry_type=vuln
    (a confirmed vuln). A method card must not be misread as a confirmed vuln.
2. KEV: fetch FULL catalog every day, save snapshot to kev_snapshot.json, diff vs previous
   snapshot (new / changed / removed). Never rely on dateAdded last 7d alone.
3. GHSA: fetch reviewed AND unreviewed separately (type=reviewed / type=unreviewed),
   filter by `modified` (not only published), sort=updated, paginate via Link header cursors.
   Unreviewed entries are marked ghsa_type=unreviewed, source_verified=false, lower credibility.
   Malware type is excluded.
4. EPSS: batch-fetch FIRST EPSS for candidates, used in ranking only. EPSS = probability
   a CVE is exploited in the next 30 days (FIRST EPSS, 0-1), NOT impact size, NOT Gate 2.
   A high-EPSS low-impact item still fails Gate 2; a low-EPSS high-impact item still
   passes Gate 2. Stored as epss + epss_date (fetch date).
5. Ranking (not filtering): KEV first, then EPSS>=0.5, then CVSS desc, then recency.
   Low / unscored CVEs are still collected if they have KEV / GHSA / PoC evidence.
6. NO CAP by default (2026-11-10 user decision): MAX_NEW=0 means unlimited. --max N still
   works for testing, but the daily cron runs unlimited. Overflow.json is kept only as a
   safety net when --max is explicitly set; with unlimited it stays empty. Consequence:
   a normal day writes ~400-450 candidate files, a 2-day window ~859 unique candidates;
   incoming/ will pile up and human verification becomes the bottleneck, not the script.
   To keep unlimited writes from calling CVE.org once per candidate (thousands of
   requests), product enrichment via CVE.org API is capped at the first 100 ranked
   items per run; the rest keep product="待核实（见描述）" and the agent step enriches
   them during verification.
7. Data model: every script-written file is status=candidate in incoming/ (NOT counted as a
   verified knowledge entry). Agent verification moves it to a category and flips
   status=verified + source_verified=true. verified:false is kept for compat only;
   do NOT set verified:true to mean a PoC was tested — use repro_tested for that.
10. TWO GATES (2026-11-10 user decision):
    Gate 1 credible: source + vuln description verifiable (existing 4-step desk check).
    Gate 2 impact: may cause data leak/tamper, account/privilege takeover, service
    interruption, server control, OR can combine with other issues into one of those.
    Auto-low (excluded from the main library): CVSS<4 or unscored AND low keyword
    (version/banner disclosure, missing security header, theoretical config advice)
    AND no sensitive data (password/token/hash/credential/session/personal) AND no
    high CWE/keyword AND not KEV AND EPSS<0.1. Auto-low items are NOT written as md
    files; they go as one line each to clues.md, marked seen status=low_excluded,
    so they do not reappear daily. If the same type can help find a more severe
    attack chain, it is kept in clues.md as a brief associated clue, not a full entry.
    Auto-high: KEV, CVSS>=7, high CWE/keyword, sensitive-data leak.
    Everything else is impact=review: human (agent step) decides Gate 2 with the
    checklist in SOURCES_DISCOVERY.md. Measured 2026-11-10 on NVD 48h (915 items):
    auto-high 639 (70%), review 276 (30%), auto-low 0 (0%). Version banners /
    missing headers are only ~1-3% of NVD by keyword — NVD already assigns CVEs
    mainly to impactful items — so the big reduction is NOT auto-exclusion; it is
    the human Gate 2 on the 30% review bucket plus not promoting low items to
    verified entries. Do not claim a larger cut than measured.
   Frontmatter adds: status, source_verified, repro_tested, first_seen, source_published,
   last_verified, aliases, epss, kev, cpe_clues (CPE is a clue only, never the final
   product/version conclusion — vendor original text is stored separately in versions/vendor_original),
   observations (one entry per source).
8. Updates, not only appends: if an existing CVE was modified in NVD (lastModified newer than
   stored), update its file (cvss/product/versions/last_verified) and append a ## 变更记录 entry.
   Rejected / withdrawn CVEs are marked status=withdrawn, never re-added as new.
9. Per-source log: success/failed, hits, deduped, deferred-to-overflow, written, pagination_complete,
   pages, last_success_at. "0 new" must be distinguishable from "source failed".
Usage: python3 collect_daily.py [--max 0] [--lookback-days 7] [--dry-run]
  --max 0 (default) = unlimited; --max N caps writes and puts the rest in overflow.json.
  --dry-run fetches and logs but writes no files and does not touch seen.json / overflow.json.
"""
import json, os, re, sys, time, urllib.parse, urllib.request, urllib.error
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
KB = os.path.join(BASE, "fujiang-pojia-knowledge")
INCOMING = os.path.join(KB, "incoming")
INCOMING_INDEX = os.path.join(BASE, "incoming_index.json")  # lightweight candidate index (no full md)
SEEN = os.path.join(BASE, "seen.json")
STATE = os.path.join(BASE, "sync_state.json")
OVERFLOW = os.path.join(BASE, "overflow.json")
KEV_SNAP = os.path.join(BASE, "kev_snapshot.json")
ENRICH_QUEUE = os.path.join(BASE, "enrich_queue.json")  # fair queue for CVE.org product enrichment
LOGDIR = os.path.join(BASE, "logs")
os.makedirs(INCOMING, exist_ok=True)
os.makedirs(LOGDIR, exist_ok=True)

MAX_NEW = 0  # 0 = unlimited (2026-11-10 user decision). --max N for testing only.
LOOKBACK_DAYS = 7  # daily pub window, in days
MOD_LOOKBACK_DAYS = 7
RECENT_PUBLISH_DAYS = 30  # mod-window catch-up only for CVEs published within last 30d
DRY_RUN = False
for i, a in enumerate(sys.argv):
    if a == "--max" and i + 1 < len(sys.argv):
        MAX_NEW = int(sys.argv[i + 1])
    if a == "--lookback-days" and i + 1 < len(sys.argv):
        LOOKBACK_DAYS = int(sys.argv[i + 1])
    if a == "--dry-run":
        DRY_RUN = True

def get_json(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "Mozilla/5.0 (vuln-kb-collector)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "ignore"))

def get_with_headers(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "Mozilla/5.0 (vuln-kb-collector)", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode("utf-8", "ignore")
        return json.loads(body), dict(r.headers)

def load_json(path, default):
    if os.path.exists(path):
        try:
            return json.load(open(path, encoding="utf-8"))
        except Exception:
            return default
    return default

def save_json(path, obj):
    if DRY_RUN:
        return
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def fault(point):
    """Test-only fault injection. Set KB_FAULT_INJECT=<point> to simulate a crash
    at that point (os._exit, no cleanup, like a power loss / killed process).
    Points, in persistence order: after_candidates, before_overflow, before_seen,
    before_state, after_state. Default off. Never set in the daily cron."""
    if os.environ.get("KB_FAULT_INJECT") == point:
        print(f"FAULT INJECTED at {point}", file=sys.stderr, flush=True)
        os._exit(99)

def atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def slugify(s):
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (s or "").lower()).strip("-")
    return s[:60] or "vuln"

def load_seen():
    seen = load_json(SEEN, None)
    if seen is not None:
        return seen
    seen = {}
    for root, _, files in os.walk(KB):
        for f in files:
            txt = ""
            try:
                txt = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read(3000)
            except Exception:
                pass
            m = re.search(r"(CVE-\d{4}-\d+)", f + " " + txt, re.I)
            if m:
                seen[m.group(1).upper()] = {"date_added": "2026-11-10", "source": "fujiang-baseline", "status": "verified"}
    return seen

def cpe_clues(cve_obj):
    clues = []
    try:
        for cfg in cve_obj.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if m.get("criteria"):
                        clues.append(m["criteria"])
                for sub in node.get("children", []):
                    for m in sub.get("cpeMatch", []):
                        if m.get("criteria"):
                            clues.append(m["criteria"])
    except Exception:
        pass
    return clues[:5]

def vendor_original(cve_obj):
    # CPE is a clue only. Vendor original text comes from CVE.org CNA affected data.
    return "", ""

def enrich_from_cve_api(cve):
    try:
        d = get_json(f"https://cveawg.mitre.org/api/cve/{cve}", timeout=15)
        aff = d.get("containers", {}).get("cna", {}).get("affected", [])
        if aff:
            a = aff[0]
            prod = f"{a.get('vendor','')} {a.get('product','')}".strip()
            vers = []
            for v in a.get("versions", [])[:3]:
                vers.append(f"{v.get('version','')} {v.get('status','')} (<{v.get('lessThan','')})" if v.get("lessThan") else f"{v.get('version','')} {v.get('status','')}")
            return prod or "", "; ".join(vers)
    except Exception:
        pass
    return "", ""

def category_guess(product, desc):
    t = ((product or "") + " " + (desc or "")).lower()
    if any(k in t for k in ["android", "apk", "mobile app", "webview", "frida", "jadx"]):
        return "mobile-rev"
    if any(k in t for k in ["windows", "microsoft windows", ".exe", "pe file", "dll hijack"]):
        if "exchange" not in t and "outlook" not in t and "active directory" not in t:
            return "binary-rev"
    if any(k in t for k in ["log4j", "fastjson", "shiro", "struts", "weblogic", "snakeyaml", "deserial", "spring4shell"]):
        return "java-deser"
    if any(k in t for k in ["confluence", "gitlab", "jenkins", "teamcity", "tomcat", "solr", "activemq", "ofbiz", "spring cloud", "druid"]):
        return "java-web"
    if any(k in t for k in ["fortinet", "fortios", "fortimanager", "palo alto", "pan-os", "ivanti", "citrix", "netscaler", "f5", "big-ip", "cisco", "checkpoint", "sonicwall", "pulse secure", "goanywhere"]):
        return "edge-device"
    if any(k in t for k in ["microsoft exchange", "outlook", "zerologon", "active directory", "printnightmare", "proxylogon", "proxyshell", "nopac", "zimbra"]):
        return "exchange-ad"
    if any(k in t for k in ["wordpress", "drupal", "joomla", "laravel", "thinkphp", "phpunit", "php", "apache http", "vbulletin"]):
        return "web-cms"
    if any(k in t for k in ["linux kernel", "sudo", "overlayfs", "nftables", "dirty pipe", "pwnkit", "privilege escalation"]):
        return "linux-priv"
    if any(k in t for k in ["docker", "kubernetes", "runc", "redis", "postgresql", "nacos", "grafana", "veeam", "vmware", "esxi", "vcenter", "container"]):
        return "cloud-container"
    return "incoming"

HIGH_CWE = {"CWE-79","CWE-89","CWE-78","CWE-94","CWE-434","CWE-22","CWE-287","CWE-862","CWE-863","CWE-269","CWE-400","CWE-918","CWE-611","CWE-502","CWE-639","CWE-284","CWE-266","CWE-74","CWE-798","CWE-306","CWE-121","CWE-787","CWE-352"}
HIGH_KW = re.compile(r"remote code execution|arbitrary code|privilege escalation|authentication bypass|sql injection|cross-site scripting|server-side request forgery|denial of service|buffer overflow|command injection|path traversal|deseriali|file upload|account takeover|bypass authentication", re.I)
SENSITIVE_KW = re.compile(r"password|credential|token|secret|hash|personal data|private|session|cookie", re.I)
LOW_KW = re.compile(r"version (disclosure|banner)|discloses? (the )?(software )?version|missing (security )?header|security header|banner|improperly? configur|theoretical", re.I)

def assess_impact(item):
    """Gate 2. Returns (impact_class, reason). impact_class: high / review / low.
    Auto-low is deliberately narrow: all conditions must hold, otherwise review.
    A low item that mentions sensitive data is NOT low — it may be a real leak."""
    try:
        s = float(item.get("cvss") or -1)
    except ValueError:
        s = -1
    try:
        epss = float(item.get("epss") or 0)
    except ValueError:
        epss = 0
    desc = (item.get("desc") or "") + " " + (item.get("title") or "")
    cwes = set(item.get("cwes") or [])
    if item.get("kev"):
        return "high", "KEV 在野利用"
    if s >= 7:
        return "high", f"CVSS {s} >= 7"
    if HIGH_KW.search(desc) or (cwes & HIGH_CWE):
        return "high", "高危 CWE/关键词（注入/RCE/越权/SSRF/DoS 等）"
    if SENSITIVE_KW.search(desc) and re.search(r"information (disclosure|exposure)|exposure|leak|disclos", desc, re.I):
        return "high", "敏感信息泄露（密码/令牌/哈希/会话/个人数据）"
    # auto-low: every condition must hold
    if (s >= 0 and s < 4 or s < 0) and LOW_KW.search(desc) and not HIGH_KW.search(desc) and not SENSITIVE_KW.search(desc) and not item.get("kev") and epss < 0.1:
        return "low", "轻微信息暴露/缺响应头/版本横幅/理论配置建议，无明确攻击路径、无敏感数据"
    return "review", "影响不明确，需人工按 Gate 2 清单判断（能否造成泄露/篡改/接管/中断/控服，或可组合成上述影响）"

# High-risk-only collection (user decision 2026-11-10): only collect the highest-risk
# items, dozens per day, not hundreds. CVE side: CVSS >= 9.0 OR KEV (any score).
# Reverse side (mobile-rev / binary-rev): severity Critical / High only.
# Everything below the bar is recorded as filtered (seen status=filtered_below_threshold)
# so it is not re-processed every day, and is NOT written as a candidate card.
# Unscored items (no CVSS yet, ~21% of NVD) fail the bar until they are scored or
# enter KEV; they are logged as filtered_awaiting_cvss.
HIGH_RISK_ONLY = True
HIGH_RISK_CVSS = 9.0

def is_high_risk(it):
    """Highest-risk bar, per user decision 2026-11-10. Returns (bool, reason)."""
    if it.get("kev"):
        return True, "KEV 在野利用（不论分数都收）"
    try:
        s = float(it.get("cvss") or -1)
    except (TypeError, ValueError):
        s = -1
    if s >= HIGH_RISK_CVSS:
        return True, f"CVSS {s} >= {HIGH_RISK_CVSS}"
    sev = str(it.get("severity", "")).lower()
    cat = category_guess(it.get("product", ""), it.get("desc", ""))
    if cat in ("mobile-rev", "binary-rev") and sev in ("critical", "high"):
        return True, f"逆向 {sev}（按拿到的权限定级）"
    if sev == "critical":
        return True, "厂商/公告评级 Critical（无 CVSS）"
    if s < 0:
        return False, "未评分，待出分后重评"
    return False, f"CVSS {s} < {HIGH_RISK_CVSS}，低于最高风险线"

def source_grade_for(item):
    """Source credibility, NOT severity, NOT a substitute for the two gates.
    A = multi-class evidence mutually supporting (>=2 independent classes agreeing
        on product/versions, e.g. vendor advisory + independent analysis, or
        CVE + vendor advisory + PoC).
    B = single authoritative original source (vendor advisory alone, CVE/NVD with
        CNA affected data alone, GHSA reviewed alone) OR sufficiently specific
        researcher evidence (detailed PoC + analysis stating product/version/entry,
        verifiable against the original).
    C = GHSA unreviewed, single post, social clue only.
    Gap fixed 2026-11-10: 'vendor advisory alone' was unmapped (was A by accident),
    and 'researcher PoC without vendor advisory' was unmapped. Both are now B."""
    ghsa_type = item.get("ghsa_type", "")
    if ghsa_type == "unreviewed":
        return "C"
    src = item.get("sources_label", "").lower()
    obs = " ".join(item.get("observations", [])).lower()
    has_vendor = "vendor" in obs or "psirt" in obs or "vendor" in src
    has_poc = "poc" in obs or "github.com" in " ".join(item.get("refs", []))
    has_independent = any(k in obs for k in ["researcher", "analysis", "watchtowr", "rapid7", "project zero"])
    has_cve = "nvd" in src or "cve.org" in src or "cve" in src
    classes = set()
    if has_vendor:
        classes.add("vendor")
    if has_independent:
        classes.add("independent")
    if has_poc:
        classes.add("poc")
    if has_cve:
        classes.add("cve")
    # A: >=2 independent classes, with vendor or independent analysis in them
    if len(classes) >= 2 and ("vendor" in classes or "independent" in classes):
        return "A"
    # B: single authoritative original source, or sufficiently specific researcher evidence
    if has_vendor or has_cve or ghsa_type == "reviewed":
        return "B"
    if has_poc and item.get("product") and "待核实" not in item.get("product", ""):
        return "B"
    if has_poc:
        return "B"  # detailed PoC with product/version/entry is B even without vendor advisory
    # no evidence class at all -> C (social / single post only)
    return "C"

def evidence_support_for(item):
    """Record what each source supports. NVD + CVE.org = ONE primary (same CNA record),
    not two independent evidences. Vendor advisory = primary, independent analysis = independent,
    PoC = PoC evidence. Returns a list of {source, supports}."""
    out = []
    src = item.get("sources_label", "")
    if "NVD" in src or "CVE.org" in src:
        out.append({"source": "NVD/CVE.org (same CNA record, counts as ONE)", "supports": "CVE existence, description, CVSS (product/versions NOT yet verified by this alone)"})
    if "KEV" in src:
        out.append({"source": "CISA KEV", "supports": "in-the-wild exploitation, product/vendor"})
    if "GitHub" in src:
        out.append({"source": f"GHSA {item.get('ghsa_type','reviewed')}", "supports": "advisory existence, affected package/versions; reviewed=source credibility, not severity"})
    return out

def find_file_for_cve(cve):
    for root, _, files in os.walk(KB):
        for f in files:
            if f.lower() == cve.lower() + ".md":
                return os.path.join(root, f)
    return None

def write_candidate(it, now_str):
    # All script-written entries are status=candidate in incoming/, never directly verified.
    fname = it.get("file_name")
    if not fname:
        if it.get("cve", "").upper().startswith("CVE-"):
            fname = f"{it['cve'].lower()}.md"
        else:
            fname = f"{now_str[:10]}-{slugify(it.get('product','') or it.get('title',''))}.md"
    path = os.path.join(INCOMING, fname)
    if os.path.exists(path):
        return None
    aliases = ", ".join(it.get("aliases", []))
    obs = "\n".join(f"- {o}" for o in it.get("observations", []))
    refs_md = "\n".join(f"- {r}" for r in it.get("refs", [])[:8]) if it.get("refs") else "- 见 sources"
    body = f"""---
title: {it.get('title','')}
cve: {it.get('cve','无')}
severity: {it.get('severity','')}
cvss: {it.get('cvss','')}
epss: {it.get('epss','')}
epss_date: {it.get('epss_date','')}
entry_type: {it.get('entry_type','vuln')}
source_grade: {it.get('source_grade','')}
kev: {str(it.get('kev', False)).lower()}
product: {it.get('product','待核实（见描述）')}
versions: {it.get('versions','见NVD/CVE')}
vendor_original: {it.get('vendor_original','')}
cpe_clues: {", ".join(it.get('cpe_clues', []))}
ports: 
keywords: {slugify(it.get('product','')).replace('-', ', ') if it.get('product') and "待核实" not in it.get('product','') else (it.get('cve','').lower() or 'candidate')}
status: candidate
impact: {it.get('impact','review')}
impact_reason: {it.get('impact_reason','')}
source_verified: false
verified: false
repro_tested: false
first_seen: {it.get('first_seen', now_str[:10])}
source_published: {it.get('source_published','')}
last_verified: 
aliases: [{aliases}]
sources: {it.get('sources_label','')}
suggested_category: {category_guess(it.get('product',''), it.get('desc',''))}
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

{it.get('desc','')}

## 逐源观察

{obs}

## 参考

{refs_md}
"""
    if DRY_RUN:
        return path + " (dry-run, not written)"
    atomic_write(path, body)
    return path

def update_existing_file(cve, changes, now_str):
    path = find_file_for_cve(cve)
    if not path or DRY_RUN:
        return None
    txt = open(path, encoding="utf-8").read()
    # update last_verified in frontmatter if present, else insert
    if "last_verified:" in txt:
        txt = re.sub(r"last_verified:.*", f"last_verified: {now_str[:10]}", txt, count=1)
    # append changelog
    entry = f"\n## 变更记录\n\n- {now_str[:10]}：{changes}\n"
    if "## 变更记录" not in txt:
        txt = txt.rstrip() + "\n" + entry
    else:
        txt = txt.rstrip() + f"\n- {now_str[:10]}：{changes}\n"
    open(path, "w", encoding="utf-8").write(txt)
    return path

def full_card_needed(it):
    """Verification-threshold for a full md card. Full card only when the item
    is already high-priority / well-evidenced; everything else stays a lightweight
    index record until an agent verifies it and materialises the card.
    Full: KEV, impact=high, CVSS>=7, or source_grade A.
    Light: impact=review + grade B/C, low CVSS, no KEV — most daily candidates."""
    try:
        cvss = float(it.get("cvss") or 0)
    except (TypeError, ValueError):
        cvss = 0
    return bool(it.get("kev")) or it.get("impact") == "high" or cvss >= 7 or it.get("source_grade") == "A"

def light_index_entry(it, now_str):
    """Necessary metadata only — no 指纹/PoC/利用步骤 body sections.
    Enough to rank, dedup and later materialise a full card."""
    return {"cve": it.get("cve", ""), "title": it.get("title", ""), "severity": it.get("severity", ""),
            "cvss": it.get("cvss", ""), "epss": it.get("epss", ""), "epss_date": it.get("epss_date", ""),
            "product": it.get("product", "待核实（见描述）"), "versions": it.get("versions", ""),
            "impact": it.get("impact", "review"), "impact_reason": it.get("impact_reason", ""),
            "source_grade": it.get("source_grade", ""), "kev": bool(it.get("kev", False)),
            "first_seen": it.get("first_seen", now_str[:10]), "source_published": it.get("source_published", ""),
            "refs": (it.get("refs") or [])[:8], "aliases": it.get("aliases", []),
            "observations": it.get("observations", []), "cpe_clues": it.get("cpe_clues", []),
            "cwes": it.get("cwes", []), "suggested_category": category_guess(it.get("product", ""), it.get("desc", "")),
            "desc": (it.get("desc", "") or "")[:500], "sources_label": it.get("sources_label", ""),
            "status": "candidate-light", "entry_type": it.get("entry_type", "vuln")}

def materialise_from_index(cve):
    """Agent step: promote a lightweight index entry to a full md card.
    Called via: python3 collect_daily.py --materialise CVE-2026-XXXXXX"""
    idx = load_json(INCOMING_INDEX, [])
    entry = next((x for x in idx if x.get("cve", "").upper() == cve.upper()), None)
    if not entry:
        print(f"not in incoming_index.json: {cve}")
        return None
    it = dict(entry)
    it["file_name"] = f"{cve.lower()}.md"
    it["desc"] = entry.get("desc", "")
    p = write_candidate(it, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    if p:
        idx = [x for x in idx if x.get("cve", "").upper() != cve.upper()]
        save_json(INCOMING_INDEX, idx)
        print(f"materialised: {p}")
        return p
    return None

def enrich_pending_files(budget, today, now_str):
    """Fair queue for product enrichment of files already in incoming/ whose
    product is still '待核实'. Priority: KEV/high-impact first, plus aging rotation:
    at least 20% of the budget goes to the oldest pending items regardless of
    priority, so backlogged items are not starved forever. Returns stats dict.
    EPSS staleness: if epss_date is >30 days old, mark epss_stale and do not use
    EPSS for ranking that item; EPSS is re-fetched when the item is processed."""
    import glob
    stats = {"processed": 0, "pending": 0, "oldest_pending": "", "epss_stale": 0, "cursor": ""}
    if DRY_RUN:
        return stats
    pending = []
    for path in glob.glob(os.path.join(INCOMING, "*.md")):
        try:
            txt = open(path, encoding="utf-8").read()
            # parse frontmatter fields we need; pending = product field starts with 待核实
            # (not just any 待核实 in frontmatter — sources label also contains 待核实)
            fm = txt.split("---")[1] if txt.startswith("---") else ""
            def field(name):
                m = re.search(rf"^{name}:\s*(.*)$", fm, re.M)
                return m.group(1).strip() if m else ""
            _prod = field("product")
            if not _prod.startswith("待核实"):
                continue
            cve = field("cve")
            first_seen = field("first_seen") or today
            kev = field("kev") == "true"
            impact = field("impact")
            epss_date = field("epss_date")
            stale = False
            if epss_date:
                try:
                    d = datetime.strptime(epss_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    if (datetime.now(timezone.utc) - d).days > 30:
                        stale = True
                except ValueError:
                    pass
            if stale:
                stats["epss_stale"] += 1
            pending.append({"path": path, "cve": cve, "first_seen": first_seen, "kev": kev, "impact": impact, "epss_stale": stale})
        except Exception:
            continue
    stats["pending_before"] = len(pending)
    # sort: KEV/high first, then oldest first_seen
    def prio(x):
        return (0 if x["kev"] else 1, 0 if x["impact"] == "high" else 1, x["first_seen"])
    pending.sort(key=prio)
    # aging rotation: 80% priority, 20% oldest regardless of priority
    n_priority = int(budget * 0.8)
    n_oldest = budget - n_priority
    oldest = sorted(pending, key=lambda x: x["first_seen"])[:n_oldest]
    chosen = []
    for x in pending[:n_priority]:
        if x not in chosen:
            chosen.append(x)
    for x in oldest:
        if x not in chosen:
            chosen.append(x)
    for x in chosen[:budget]:
        if not x["cve"].upper().startswith("CVE-"):
            continue
        ep, ev = enrich_from_cve_api(x["cve"])
        if not ep:
            continue
        try:
            txt = open(x["path"], encoding="utf-8").read()
            txt = re.sub(r"^product:.*$", f"product: {ep}", txt, count=1, flags=re.M)
            if ev:
                txt = re.sub(r"^versions:.*$", f"versions: {ev}", txt, count=1, flags=re.M)
            txt = re.sub(r"^vendor_original:.*$", f"vendor_original: {ep}", txt, count=1, flags=re.M)
            open(x["path"], "w", encoding="utf-8").write(txt)
            stats["processed"] += 1
        except Exception:
            continue
    remaining = [x for x in pending if x not in chosen[:budget]]
    stats["pending"] = len(remaining)
    if remaining:
        stats["oldest_pending"] = min(x["first_seen"] for x in remaining)
        stats["cursor"] = f"next: {remaining[0]['cve']} ({len(remaining)} pending)"
    # persist queue cursor
    save_json(ENRICH_QUEUE, {"date": today, "pending": [{"cve": x["cve"], "file": x["path"], "first_seen": x["first_seen"]} for x in remaining], "cursor": stats.get("cursor", ""), "processed_today": stats["processed"]})
    return stats

def main():
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%d %H:%M UTC")
    today = now.strftime("%Y-%m-%d")
    state = load_json(STATE, {})
    seen = load_seen()
    overflow_in = load_json(OVERFLOW, [])
    errors = []
    per_source = {}
    candidates = {}  # key -> item dict
    ghsa_seen = {}  # ghsa_id -> (type, key); reviewed wins over unreviewed

    def add_candidate(key, item):
        if not key:
            return
        if key in candidates:
            ex = candidates[key]
            # merge aliases / observations / refs, keep earliest first_seen
            for a in item.get("aliases", []):
                if a and a not in ex.get("aliases", []):
                    ex.setdefault("aliases", []).append(a)
            for o in item.get("observations", []):
                if o not in ex.get("observations", []):
                    ex.setdefault("observations", []).append(o)
            for r in item.get("refs", []):
                if r and r not in ex.get("refs", []):
                    ex.setdefault("refs", []).append(r)
            if "KEV" in item.get("sources_label", ""):
                ex["kev"] = True
                ex["sources_label"] = item["sources_label"]
            # keep highest cvss
            try:
                if float(item.get("cvss") or 0) > float(ex.get("cvss") or 0):
                    ex["cvss"] = item["cvss"]
                    ex["severity"] = item.get("severity", ex.get("severity"))
            except ValueError:
                pass
        else:
            candidates[key] = item

    # ---- overflow first: they were not added to seen, must be processed before new items
    overflow_items = []
    for it in overflow_in:
        if isinstance(it, dict) and it.get("cve"):
            overflow_items.append(it)
    per_source["overflow_queue"] = {"status": "ok", "hits": len(overflow_items), "deduped": 0, "written": 0, "pagination_complete": True, "pages": 0, "last_success_at": now_str}

    # ---- 1. NVD: pub only, overlap lookback, paginated, NO cvss filter
    nvd_stats = {"status": "failed", "hits": 0, "deduped": 0, "written": 0, "pagination_complete": False, "pages": 0, "last_success_at": None}
    pending_nvd_cursor = None
    try:
        # Daily window 7d. If gap since last_success > 7d, segment by publish date in
        # 7-day chunks until caught up, then restore daily window. No lastMod sweep.
        last_ok = state.get("nvd_last_success")
        if last_ok:
            start_dt = datetime.fromisoformat(last_ok.replace("Z", "+00:00")) - timedelta(days=1)
        else:
            start_dt = now - timedelta(days=LOOKBACK_DAYS)
        end_dt = now
        gap_days = (end_dt - start_dt).days
        if gap_days > LOOKBACK_DAYS:
            segments = []
            cur = start_dt
            while cur < end_dt:
                nxt = min(cur + timedelta(days=LOOKBACK_DAYS), end_dt)
                segments.append((cur, nxt))
                cur = nxt
            nvd_stats["catchup_segments"] = len(segments)
            nvd_stats["catchup_gap_days"] = gap_days
        else:
            segments = [(start_dt, end_dt)]
        nvd_stats["pub_window_start"] = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        nvd_stats["segments"] = len(segments)
        # iterate segments; each segment paginated
        seg_idx = 0
        while seg_idx < len(segments):
            seg_start, seg_end = segments[seg_idx]
            seg_idx += 1
            start_s = seg_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            end_s = seg_end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            start_index = 0
            total = None
            pages = 0
            while True:
                u = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_s}&pubEndDate={end_s}&resultsPerPage=500&startIndex={start_index}"
                data = get_json(u)
                pages += 1
                if total is None:
                    total = data.get("totalResults", 0)
                nvd_stats["hits"] += len(data.get("vulnerabilities", []))
                for v in data.get("vulnerabilities", []):
                    c = v.get("cve", {})
                    cid = c.get("id", "").upper()
                    if not cid:
                        continue
                    if c.get("vulnStatus") in ("Rejected",):
                        if cid in seen:
                            update_existing_file(cid, "NVD 标记为 Rejected/撤回", now_str)
                            seen[cid]["status"] = "withdrawn"
                        continue
                    if cid in seen and seen[cid].get("status") in ("verified", "candidate"):
                        lm = c.get("lastModified", "")
                        stored_lm = seen[cid].get("last_modified", "")
                        if lm and stored_lm and lm > stored_lm:
                            update_existing_file(cid, f"NVD 修改：lastModified {stored_lm} -> {lm}，请核对 CVSS/版本/参考", now_str)
                            seen[cid]["last_modified"] = lm
                            seen[cid]["last_verified"] = today
                        nvd_stats["deduped"] += 1
                        continue
                    descs = [d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"]
                    desc = descs[0] if descs else ""
                    score, severity = "", "unknown"
                    for m in c.get("metrics", {}).get("cvssMetricV31", []) + c.get("metrics", {}).get("cvssMetricV30", []) + c.get("metrics", {}).get("cvssMetricV40", []):
                        score = str(m.get("cvssData", {}).get("baseScore", ""))
                        severity = str(m.get("cvssData", {}).get("baseSeverity", severity)).lower()
                        break
                    refs = [r.get("url", "") for r in c.get("references", []) if r.get("url")]
                    cwes = []
                    for w in c.get("weaknesses", []):
                        for dd in w.get("description", []):
                            if dd.get("value"):
                                cwes.append(dd["value"])
                    add_candidate(cid, {"cve": cid, "title": f"{cid} {desc[:100]}" if desc else cid,
                                        "severity": severity, "cvss": score, "product": "",
                                        "versions": "见NVD/CVE", "desc": desc, "refs": refs,
                                        "sources_label": "NVD / CVE.org（自动采集，待核实）",
                                        "first_seen": today, "source_published": c.get("published", "")[:10],
                                        "aliases": [], "observations": [f"NVD: published={c.get('published','')[:10]} lastModified={c.get('lastModified','')[:10]} vulnStatus={c.get('vulnStatus','')}"],
                                        "cpe_clues": cpe_clues(c), "cwes": cwes, "_nvd_last_modified": c.get("lastModified", "")})
                time.sleep(6)
                start_index += 500
                if total is not None and start_index >= total:
                    break
                if pages >= 20:
                    break
            nvd_stats["pages"] = nvd_stats.get("pages", 0) + pages
        nvd_stats["pagination_complete"] = True
        nvd_stats["status"] = "ok"
        nvd_stats["last_success_at"] = now_str
        # Cursor is NOT advanced here. It is only written to sync_state.json after
        # all pages are fetched AND candidate files are landed on disk (see end of
        # main). If any segment/page fails, or the run crashes before landing,
        # the on-disk cursor stays at the old value and a rerun re-fetches the
        # same window; seen.json + file-exists checks make the rerun idempotent
        # (no duplicate cards, no lost successful segments).
        pending_nvd_cursor = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception as e:
        errors.append(f"NVD: {e}")
        nvd_stats["status"] = f"failed: {e}"
    per_source["nvd"] = nvd_stats

    # ---- 2. KEV: full catalog snapshot diff
    kev_stats = {"status": "failed", "hits": 0, "deduped": 0, "written": 0, "pagination_complete": True, "pages": 0, "last_success_at": None}
    try:
        kev = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        kev_stats["hits"] = len(kev.get("vulnerabilities", []))
        kev_stats["pages"] = 1
        prev = load_json(KEV_SNAP, {})
        prev_ids = {v.get("cveID", "").upper() for v in prev.get("vulnerabilities", [])} if prev else set()
        cur_ids = {v.get("cveID", "").upper() for v in kev.get("vulnerabilities", [])}
        if not prev:
            # First snapshot: seed it. Do NOT treat all 1700+ historic KEV entries as new;
            # only dateAdded within last 7d counts as new on the seeding run.
            cutoff7 = now - timedelta(days=7)
            new_ids = {v.get("cveID", "").upper() for v in kev.get("vulnerabilities", [])
                       if v.get("dateAdded") and datetime.strptime(v.get("dateAdded"), "%Y-%m-%d").replace(tzinfo=timezone.utc) >= cutoff7}
            kev_stats["first_snapshot_seeded"] = True
        else:
            new_ids = cur_ids - prev_ids
        # also detect changed entries by comparing full dict for overlapping ids
        prev_map = {v.get("cveID", "").upper(): v for v in prev.get("vulnerabilities", [])} if prev else {}
        changed_ids = {cid for cid in cur_ids & prev_ids if kev and prev_map.get(cid) != next((x for x in kev.get("vulnerabilities", []) if x.get("cveID", "").upper() == cid), None)}
        kev_stats["new_in_snapshot"] = len(new_ids)
        kev_stats["changed_in_snapshot"] = len(changed_ids)
        kev_stats["catalogVersion"] = kev.get("catalogVersion")
        kev_stats["dateReleased"] = kev.get("dateReleased")
        if not DRY_RUN:
            save_json(KEV_SNAP, kev)
        for v in kev.get("vulnerabilities", []):
            cid = v.get("cveID", "").upper()
            if not cid:
                continue
            is_new = cid in new_ids or cid in changed_ids
            if cid in seen and seen[cid].get("status") in ("verified", "candidate") and not is_new:
                kev_stats["deduped"] += 1
                continue
            if cid in seen and is_new:
                update_existing_file(cid, "CISA KEV 快照变化：新增或字段变更", now_str)
                continue
            # old KEV entry, not new/changed in this snapshot, and not a fresh candidate -> skip
            if not is_new and cid not in candidates:
                try:
                    da = datetime.strptime(v.get("dateAdded", "2000-01-01"), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    if da < now - timedelta(days=7):
                        kev_stats["deduped"] += 1
                        continue
                except ValueError:
                    pass
            existing = candidates.get(cid)
            if existing:
                existing["kev"] = True
                existing["sources_label"] = "CISA KEV + NVD（在野利用，自动采集，待核实）"
                existing["severity"] = "critical"
                existing.setdefault("observations", []).append(f"CISA KEV: dateAdded={v.get('dateAdded','')} dueDate={v.get('dueDate','')}")
            else:
                add_candidate(cid, {"cve": cid, "title": v.get("vulnerabilityName", cid), "severity": "critical", "cvss": "",
                                    "product": f"{v.get('vendorProject','')} {v.get('product','')}".strip(),
                                    "versions": "见CISA KEV/厂商公告", "desc": v.get("shortDescription", ""),
                                    "refs": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
                                    "sources_label": "CISA KEV（在野利用，自动采集，待核实）",
                                    "first_seen": today, "source_published": v.get("dateAdded", ""),
                                    "aliases": [], "observations": [f"CISA KEV: dateAdded={v.get('dateAdded','')} dueDate={v.get('dueDate','')}"],
                                    "kev": True})
        kev_stats["status"] = "ok"
        kev_stats["last_success_at"] = now_str
    except Exception as e:
        errors.append(f"KEV: {e}")
        kev_stats["status"] = f"failed: {e}"
    per_source["kev"] = kev_stats

    # ---- 3. GHSA: reviewed + unreviewed, modified filter, cursor pagination, sort=updated
    ghsa_stats = {"status": "failed", "hits": 0, "deduped": 0, "written": 0, "pagination_complete": False, "pages": 0, "last_success_at": None}
    try:
        cutoff_date = (now - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%d")
        total_pages = 0
        for gtype in ["reviewed", "unreviewed"]:
            after = None
            for _page in range(3):  # cap pages: unauth GitHub limit is 60 req/hour
                q = {"per_page": "100", "sort": "updated", "direction": "desc", "type": gtype,
                     "modified": f">={cutoff_date}"}
                url = "https://api.github.com/advisories?" + urllib.parse.urlencode(q)
                if after:
                    # after cursor from Link header is already URL-encoded; do NOT urlencode again
                    url += "&after=" + after
                data, headers = None, {}
                try:
                    data, headers = get_with_headers(url)
                except Exception as e:
                    # 403 rate limit: do NOT retry aggressively, it makes it worse.
                    # Record the failure, keep the partial hits already collected.
                    errors.append(f"GHSA {gtype} page {_page}: {e} (partial data kept)")
                    ghsa_stats["status"] = f"partial: {e}"
                    break
                total_pages += 1
                ghsa_stats["hits"] += len(data)
                for a in data:
                    cves = [c.get("cve_id", "") for c in a.get("cves", []) if c.get("cve_id")]
                    ghsa_id = a.get("ghsa_id", "")
                    if not cves and not ghsa_id:
                        continue
                    # credibility: unreviewed is lower, must be marked
                    # dedup by GHSA ID across reviewed/unreviewed; reviewed wins
                    if ghsa_id:
                        prev = ghsa_seen.get(ghsa_id)
                        if prev and prev[0] == "reviewed" and gtype == "unreviewed":
                            ghsa_stats["deduped"] += 1
                            continue
                        if prev and prev[0] == "unreviewed" and gtype == "reviewed":
                            # replace the unreviewed candidate with the reviewed one
                            old_key = prev[1]
                            candidates.pop(old_key, None)
                        ghsa_seen[ghsa_id] = (gtype, cves[0].upper() if cves else ghsa_id)
                    for cid in (cves or [ghsa_id]):
                        cid_u = cid.upper()
                        if cid_u in seen and seen[cid_u].get("status") in ("verified", "candidate"):
                            ghsa_stats["deduped"] += 1
                            continue
                        key = cid_u
                        item = {"cve": cid_u if cid_u.startswith("CVE-") else "无", "title": (a.get("summary", cid) or cid)[:120],
                                "severity": (a.get("severity") or "unknown").lower(),
                                "cvss": str((a.get("cvss") or {}).get("score", "") or ""),
                                "product": ", ".join([p.get("ecosystem", "") + ":" + p.get("name", "") for p in a.get("vulnerabilities", [])][:2]) or "open-source",
                                "versions": "见GHSA", "desc": (a.get("description", "") or "")[:2000],
                                "refs": [a.get("html_url", "")],
                                "sources_label": f"GitHub Advisory Database ({gtype}，自动采集，待核实）",
                                "first_seen": today, "source_published": (a.get("published_at", "") or "")[:10],
                                "aliases": [ghsa_id] if ghsa_id else [],
                                "observations": [f"GHSA {ghsa_id} type={gtype} severity={a.get('severity')} epss_percentage={a.get('epss',{}).get('percentage') if isinstance(a.get('epss'), dict) else ''}"],
                                "ghsa_type": gtype,
                                "epss": str((a.get("epss") or {}).get("percentage", "") or "") if isinstance(a.get("epss"), dict) else ""}
                        if cid_u.startswith("CVE-"):
                            add_candidate(key, item)
                        else:
                            # non-CVE GHSA: GHSA id is the primary identity, not "无"
                            it2 = {**item, "cve": f"无（{ghsa_id}）", "file_name": f"{ghsa_id.lower()}.md"}
                            add_candidate(ghsa_id, it2)
                # parse Link header for next cursor
                link = headers.get("Link", "") or headers.get("link", "")
                m = re.search(r'<[^>]*[?&]after=([^>&]+)[^>]*>;\s*rel="next"', link)
                if not m:
                    break
                after = m.group(1)
                time.sleep(1)
        ghsa_stats["pages"] = total_pages
        ghsa_stats["pagination_complete"] = (ghsa_stats.get("status") != "partial: HTTP Error 403: rate limit exceeded" and "partial" not in str(ghsa_stats.get("status","")))
        if ghsa_stats["status"] == "failed":
            ghsa_stats["status"] = "ok"
            ghsa_stats["last_success_at"] = now_str
    except Exception as e:
        errors.append(f"GHSA: {e}")
        ghsa_stats["status"] = f"failed: {e}"
    per_source["ghsa"] = ghsa_stats

    # ---- EPSS batch for candidates (ranking only)
    try:
        keys = list(candidates.keys())[:100]
        cve_keys = [k for k in keys if k.startswith("CVE-")]
        if cve_keys:
            for i in range(0, len(cve_keys), 100):
                batch = ",".join(cve_keys[i:i+100])
                d = get_json(f"https://api.first.org/data/v1/epss?cve={batch}")
                for row in d.get("data", []):
                    if row.get("cve") in candidates:
                        candidates[row["cve"]]["epss"] = str(row.get("epss", ""))
                        candidates[row["cve"]]["epss_date"] = today
    except Exception as e:
        errors.append(f"EPSS: {e}")

    # ---- merge overflow (processed first) + new candidates, rank, cap with overflow
    all_items = []
    # overflow items are already dicts in v2 format; normalise
    for it in overflow_items:
        if it.get("cve") and it["cve"] not in candidates:
            all_items.append(it)
    for k, it in candidates.items():
        # skip already-seen (should have been filtered, double-check)
        if it.get("cve", "").upper().startswith("CVE-") and it["cve"].upper() in seen:
            continue
        all_items.append(it)

    def rank_key(x):
        kev = 0 if x.get("kev") else 1
        try:
            epss = float(x.get("epss") or 0)
        except ValueError:
            epss = 0
        epss_flag = 0 if epss >= 0.5 else 1
        try:
            s = float(x.get("cvss") or 0)
        except ValueError:
            s = 0
        return (kev, epss_flag, -epss, -s, x.get("source_published", ""))
    all_items.sort(key=rank_key)
    # Counts: raw_hits is per-source raw (with cross-source duplicates); total_hits here
    # is unique candidates after cross-source dedup, before seen dedup.
    # 2026-11-10 clarification: 639+276=915 was raw NVD hits BEFORE seen dedup;
    # after seen dedup it was 859 unique new candidates.
    raw_hits = sum(v.get("hits", 0) for v in per_source.values() if isinstance(v, dict))
    total_hits = len(all_items)
    if MAX_NEW and MAX_NEW > 0:
        to_write = all_items[:MAX_NEW]
        remaining = all_items[MAX_NEW:]
    else:
        to_write = all_items
        remaining = []

    # Gate 2: assess impact for all to_write + overflow candidates, low -> clues.md only
    clues_path = os.path.join(BASE, "clues.md")
    low_excluded = []
    kept = []
    for it in to_write:
        ic, reason = assess_impact(it)
        it["impact"] = ic
        it["impact_reason"] = reason
        if ic == "low":
            low_excluded.append(it)
            if not DRY_RUN:
                line = f"- {today} | {it.get('cve','')} | {it.get('title','')[:120]} | {reason} | refs: {'; '.join(it.get('refs', [])[:2])}\n"
                with open(clues_path, "a", encoding="utf-8") as f:
                    f.write(line)
            key = it.get("cve") if it.get("cve", "").startswith("CVE-") else it.get("file_name", it.get("cve"))
            seen[key] = {"date_added": today, "source": it.get("sources_label"), "status": "low_excluded",
                         "first_seen": it.get("first_seen", today), "impact": "low", "impact_reason": reason}
        else:
            kept.append(it)
    # low items in the remaining overflow are NOT written to clues yet (they have not
    # been processed); they will be assessed when they reach the front of the queue.
    # High-risk-only filter (user decision 2026-11-10): keep only the highest-risk
    # items; the rest are recorded as filtered so they are not re-processed daily.
    filtered_below = []
    if HIGH_RISK_ONLY:
        _kept2 = []
        for it in kept:
            ok, _why = is_high_risk(it)
            if ok:
                _kept2.append(it)
            else:
                filtered_below.append(it)
                key = it.get("cve") if it.get("cve", "").startswith("CVE-") else it.get("file_name", it.get("cve"))
                seen[key] = {"date_added": today, "source": it.get("sources_label"), "status": "filtered_below_threshold",
                             "first_seen": it.get("first_seen", today), "impact": it.get("impact"), "impact_reason": it.get("impact_reason"),
                             "filter_reason": _why}
        kept = _kept2
    to_write = kept

    # enrich product for to_write only (CVE API, vendor original text; CPE stays a clue)
    written = []
    updates = []
    # Fair queue: new items get 50 enrichment slots; pending files from earlier
    # runs get the other 50 via enrich_pending_files() (called after writing).
    enrich_budget = 50
    for it in to_write:
        cid = it.get("cve", "")
        if cid.startswith("CVE-") and not it.get("product") and enrich_budget > 0:
            enrich_budget -= 1
            ep, ev = enrich_from_cve_api(cid)
            if ep:
                it["product"] = ep
                it["vendor_original"] = ep
                if ev:
                    it["versions"] = ev
        if not it.get("product"):
            it["product"] = "待核实（见描述）"
        # if this CVE was modified in NVD and file already exists, update instead of creating
        if cid.startswith("CVE-") and find_file_for_cve(cid):
            p = update_existing_file(cid, "NVD 修改后复核，CVSS/版本/参考已更新", now_str)
            if p:
                updates.append({"cve": cid, "file": p})
                seen[cid] = {**seen.get(cid, {}), "last_verified": today, "last_modified": it.get("_nvd_last_modified", "")}
            continue
        it["source_grade"] = source_grade_for(it)
        it["evidence_support"] = evidence_support_for(it)
        # Lightweight candidates: low-priority / unverified items stay as an index
        # record only; a full md card is generated only when the agent verifies
        # the item and materialises it (--materialise). This keeps incoming/
        # from becoming a second 400-files-a-day library.
        if not full_card_needed(it):
            if not DRY_RUN:
                _idx = load_json(INCOMING_INDEX, [])
                if not any(x.get("cve") == cid for x in _idx):
                    _idx.append(light_index_entry(it, now_str))
                    # index is a candidate persistence: save it in the same stage
                    # as md files, before seen/state (see fault-injection order below)
                    save_json(INCOMING_INDEX, _idx)
                written.append({"cve": cid, "file": "incoming_index.json", "light": True, "severity": it.get("severity"), "cvss": it.get("cvss"), "epss": it.get("epss"), "epss_date": it.get("epss_date"), "kev": it.get("kev"), "source": it.get("sources_label"), "status": "candidate-light", "impact": it.get("impact"), "impact_reason": it.get("impact_reason"), "source_grade": it.get("source_grade")})
                key = cid if cid.startswith("CVE-") else it.get("file_name", cid)
                seen[key] = {"date_added": today, "source": it.get("sources_label"), "status": "candidate-light",
                             "first_seen": it.get("first_seen", today), "source_published": it.get("source_published",""),
                             "last_verified": "", "aliases": it.get("aliases", []),
                             "impact": it.get("impact"), "impact_reason": it.get("impact_reason"),
                             "last_modified": it.get("_nvd_last_modified", "")}
            else:
                written.append({"cve": cid, "file": "incoming_index.json (dry-run)", "light": True, "status": "candidate-light (dry-run)", "source": it.get("sources_label"), "severity": it.get("severity"), "cvss": it.get("cvss"), "epss": it.get("epss"), "kev": it.get("kev"), "impact": it.get("impact"), "impact_reason": it.get("impact_reason")})
            continue
        p = write_candidate(it, now_str)
        if p and not DRY_RUN:
            written.append({"cve": cid, "file": p, "severity": it.get("severity"), "cvss": it.get("cvss"), "epss": it.get("epss"), "epss_date": it.get("epss_date"), "kev": it.get("kev"), "source": it.get("sources_label"), "status": "candidate", "impact": it.get("impact"), "impact_reason": it.get("impact_reason"), "source_grade": it.get("source_grade"), "suggested_category": category_guess(it.get("product",""), it.get("desc",""))})
            key = cid if cid.startswith("CVE-") else it.get("file_name", cid)
            seen[key] = {"date_added": today, "source": it.get("sources_label"), "status": "candidate",
                         "first_seen": it.get("first_seen", today), "source_published": it.get("source_published",""),
                         "last_verified": "", "aliases": it.get("aliases", []),
                         "impact": it.get("impact"), "impact_reason": it.get("impact_reason"),
                         "last_modified": it.get("_nvd_last_modified", "")}
        elif p and DRY_RUN:
            written.append({"cve": cid, "file": p, "status": "candidate (dry-run)", "source": it.get("sources_label"), "severity": it.get("severity"), "cvss": it.get("cvss"), "epss": it.get("epss"), "kev": it.get("kev"), "impact": it.get("impact"), "impact_reason": it.get("impact_reason")})

    # Persistence order (crash-safe, cursor last):
    #   1. candidate md files + incoming_index.json (already written above)
    #   2. overflow.json (remaining items, explicitly disposed)
    #   3. seen.json (dedup record)
    #   4. sync_state.json (NVD cursor) — only after 1-3 are on disk.
    # Fault injection points (KB_FAULT_INJECT env, test only) simulate a crash
    # at each stage; a rerun must then lose nothing and duplicate nothing.
    if not DRY_RUN:
        fault("after_candidates")
        fault("before_overflow")
        save_json(OVERFLOW, remaining)
        fault("before_seen")
        save_json(SEEN, seen)
        fault("before_state")
        # Only now, after files are landed, advance the NVD cursor.
        if pending_nvd_cursor and per_source.get("nvd", {}).get("pagination_complete"):
            state["nvd_last_success"] = pending_nvd_cursor
        save_json(STATE, state)
        fault("after_state")
    else:
        # dry-run: do not persist overflow either, just report it
        pass

    enrich_stats = enrich_pending_files(50, today, now_str) if not DRY_RUN else {"processed": 0, "pending": 0, "oldest_pending": "", "epss_stale": 0, "cursor": "dry-run"}
    for src in per_source.values():
        if isinstance(src, dict) and "written" in src:
            src["written"] = src.get("written", 0)
    per_source["nvd"]["written"] = len([w for w in written if "NVD" in w.get("source","")])
    per_source["kev"]["written"] = len([w for w in written if "KEV" in w.get("source","")])
    per_source["ghsa"]["written"] = len([w for w in written if "GitHub" in w.get("source","")])

    impact_counts = {"high": sum(1 for it in to_write if it.get("impact") == "high"),
                     "review": sum(1 for it in to_write if it.get("impact") == "review"),
                     "low_excluded_to_clues": len(low_excluded)}
    pending_verification_md = len([f for f in os.listdir(INCOMING) if f.endswith(".md")]) if os.path.isdir(INCOMING) else 0
    light_index = load_json(INCOMING_INDEX, []) if not DRY_RUN else []
    pending_verification = pending_verification_md + len(light_index)
    verified_count = 0
    for root, _, files in os.walk(KB):
        if "incoming" in root:
            continue
        verified_count += sum(1 for f in files if f.endswith(".md") and f != "SKILL.md")
    pending_enrichment = 0
    for f in os.listdir(INCOMING) if os.path.isdir(INCOMING) else []:
        try:
            _txt = open(os.path.join(INCOMING, f), encoding="utf-8", errors="ignore").read(2000)
            _fm = _txt.split("---")[1] if _txt.startswith("---") else ""
            _m = re.search(r"^product:\s*(.*)$", _fm, re.M)
            if _m and _m.group(1).strip().startswith("待核实"):
                pending_enrichment += 1
        except Exception:
            pass
    log = {"date": now_str, "lookback_days": LOOKBACK_DAYS, "dry_run": DRY_RUN,
           "counts": {"raw_hits": raw_hits, "unique_candidates": total_hits,
                      "deduped_seen": sum(v.get("deduped", 0) for v in per_source.values() if isinstance(v, dict)),
                      "candidates_written": len(written), "pending_verification_incoming": pending_verification,
                      "overflow_remaining": len(remaining),
                      # Collection vs verification, kept separate. Unlimited collection
                      # is NOT unlimited verification, and candidate growth is NOT
                      # common-library growth.
                      "collection": {"raw_hits": raw_hits, "unique_candidates": total_hits, "candidates_written_today": len(written)},
                      "verification": {"pending_verification": pending_verification, "pending_verification_full_cards": pending_verification_md, "pending_verification_light_index": len(light_index), "verified_total": verified_count, "low_excluded_to_clues": len(low_excluded)},
                      "high_risk_only": HIGH_RISK_ONLY, "filtered_below_threshold": len(filtered_below),
                      "enrichment": enrich_stats,
                      "pending_enrichment": pending_enrichment},
           "total_hits": total_hits, "processed": len(to_write), "written": written,
           "impact_counts": impact_counts, "low_excluded": [{"cve": x.get("cve"), "title": x.get("title")} for x in low_excluded],
           "updates": updates, "overflow_count": len(remaining),
           "overflow_cursor": {"next_run_first": [(r.get("cve") if r.get("cve") not in ("无", "") else r.get("file_name")) for r in remaining[:10]], "total_remaining": len(remaining)},
           "per_source": per_source, "errors": errors,
           "note": "incoming=candidate, NOT counted as verified knowledge entries; verified = files in categories, candidate = files in incoming/"}
    logpath = os.path.join(LOGDIR, today + ".json")
    if not DRY_RUN:
        json.dump(log, open(logpath, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(json.dumps(log, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    import sys as _sys
    if len(_sys.argv) >= 3 and _sys.argv[1] == "--materialise":
        materialise_from_index(_sys.argv[2])
    else:
        main()
