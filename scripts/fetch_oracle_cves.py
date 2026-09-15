#!/usr/bin/env python3
"""Track critical-severity Oracle CVEs and write one Markdown page per CVE.

Authoritative data comes from the CVE Program's CVE List V5
(https://github.com/CVEProject/cvelistV5), which publishes the record exactly
as the assigning CNA wrote it. Oracle is a CNA, so its own CVSS score is
available the moment a Critical Patch Update ships.

Two discovery modes feed one shared renderer:

  delta    Read the CVE List's rolling change log for recently published or
           updated records. This is the fast path -- it sees an Oracle CVE
           within the hour. Used by CI.
  backfill Enumerate Oracle CVEs over a historical date range using the NVD
           API, which can filter by CPE vendor server-side. Used once to
           populate the repository.

Patch binaries are never mirrored here. Oracle distributes them only through
My Oracle Support under a support contract; pages link to Oracle's advisories.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

CVE5_RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
DELTA_LOG_URL = f"{CVE5_RAW_BASE}/deltaLog.json"
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD rejects any requested date range wider than 120 days.
MAX_WINDOW_DAYS = 120
# Anonymous NVD callers get 5 requests per 30s; an API key raises it to 50.
NVD_SLEEP_NO_KEY = 6.5
NVD_SLEEP_WITH_KEY = 0.8
NVD_PAGE_SIZE = 2000

# raw.githubusercontent.com serves static files, so modest parallelism is fine
# and turns a few hundred sequential fetches into a few seconds of work.
RAW_WORKERS = 8

REPO_SLUG = os.environ.get("TRACKER_REPO", "REPLACE_ME/oracle-cve-tracker")
REPO_URL = f"https://github.com/{REPO_SLUG}"
CHANNEL_URL = "https://t.me/oraclepdchannel"
BOT_URL = "https://t.me/oraclepdbot"
ORACLE_ADVISORY_URL = "https://www.oracle.com/security-alerts/"

CVE_ID_PATTERN = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
# A real weakness classification starts with a CWE identifier, e.g.
# "CWE-79 Cross-site Scripting". Anything else in problemTypes is prose.
CWE_PATTERN = re.compile(r"^CWE-\d+", re.IGNORECASE)


class FetchError(RuntimeError):
    """Raised when an upstream source cannot be reached or returns garbage."""


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def http_get_json(url: str, headers: dict | None = None, max_retries: int = 4):
    """GET a URL and parse JSON, retrying only on transient failures.

    A 404 means the record genuinely is not there and retrying cannot help, so
    non-retryable statuses raise immediately instead of burning the retry budget.
    """
    request_headers = {"User-Agent": "oracle-cve-tracker/1.0"}
    if headers:
        request_headers.update(headers)

    retryable = {403, 429, 500, 502, 503, 504}

    for attempt in range(max_retries):
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return json.loads(response.read().decode("utf-8"))

        except urllib.error.HTTPError as exc:
            if exc.code not in retryable or attempt == max_retries - 1:
                raise FetchError(f"HTTP {exc.code} for {url}") from exc
            time.sleep(2 ** attempt * 5)  # 5s, 10s, 20s; NVD limits reset in 30s.

        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == max_retries - 1:
                raise FetchError(f"Cannot reach {url}: {exc}") from exc
            time.sleep(2 ** attempt * 5)

        except json.JSONDecodeError as exc:
            # A proxy or captive portal answered with HTML instead of JSON.
            raise FetchError(f"Invalid JSON from {url}: {exc}") from exc

    raise FetchError(f"Exhausted retries for {url}")


def cve5_raw_url(cve_id: str) -> str:
    """Build the CVE List V5 path for an ID.

    Records are bucketed by year and by the ID's thousands block, so
    CVE-2026-21953 lives at cves/2026/21xxx/CVE-2026-21953.json.
    """
    match = CVE_ID_PATTERN.match(cve_id)
    if not match:
        raise ValueError(f"Malformed CVE ID: {cve_id}")
    year, number = match.groups()
    bucket = f"{number[:-3]}xxx" if len(number) > 3 else "0xxx"
    return f"{CVE5_RAW_BASE}/{year}/{bucket}/{cve_id}.json"


def fetch_record(cve_id: str) -> dict | None:
    """Fetch one CVE Record v5, returning None if it is absent or unreadable.

    A single missing record must not abort a run of several hundred, so this
    swallows its own errors and reports them on stderr.
    """
    try:
        return http_get_json(cve5_raw_url(cve_id))
    except (FetchError, ValueError) as exc:
        print(f"  skipping {cve_id}: {exc}", file=sys.stderr)
        return None


def fetch_records(cve_ids: list[str]) -> list[dict]:
    """Fetch many records in parallel, preserving only the successful ones."""
    if not cve_ids:
        return []
    with ThreadPoolExecutor(max_workers=RAW_WORKERS) as pool:
        results = pool.map(fetch_record, cve_ids)
    return [record for record in results if record]


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def discover_from_delta(days: int, tracked: set[str]) -> list[str]:
    """Return CVE IDs changed in the CVE List within the last `days` days.

    The change log carries only IDs and links, not the assigner, so Oracle
    ownership cannot be decided until each record is fetched. To keep that
    affordable we take every newly published record, but among merely updated
    records we take only ones already tracked here -- an update to a CVE that
    was never Oracle's stays irrelevant.
    """
    print(f"Reading CVE List change log (last {days} days)", file=sys.stderr)
    log = http_get_json(DELTA_LOG_URL)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    candidates: set[str] = set()

    for entry in log:
        fetched_at = entry.get("fetchTime")
        if not fetched_at:
            continue
        try:
            stamp = datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        if stamp < cutoff:
            continue

        for item in entry.get("new") or []:
            cve_id = item.get("cveId")
            if cve_id:
                candidates.add(cve_id)

        for item in entry.get("updated") or []:
            cve_id = item.get("cveId")
            if cve_id and cve_id in tracked:
                candidates.add(cve_id)

    print(f"  {len(candidates)} candidate records to inspect", file=sys.stderr)
    return sorted(candidates)


def discover_from_nvd(start: datetime, end: datetime) -> list[str]:
    """Return Oracle CVE IDs published in a date range, via the NVD API.

    NVD can filter by CPE vendor server-side, which makes historical backfill
    two requests instead of scanning the whole CVE List. We match on
    `virtualMatchString=cpe:2.3:*:oracle` rather than a keyword, because
    keyword search also hits products that merely mention Oracle compatibility.

    Severity is deliberately not filtered here. NVD's `cvssV3Severity`
    parameter matches only NVD's own Primary score, and NVD enrichment lags
    badly: of 1108 Oracle CVEs published in July 2026, 1108 carried an
    Oracle-assigned score but only 4 had an NVD one. Filtering server-side
    returned 1 critical CVE where 211 were genuinely critical.
    """
    api_key = os.environ.get("NVD_API_KEY") or None
    if not api_key:
        print("No NVD_API_KEY set; using the slower anonymous rate limit.", file=sys.stderr)
    pause = NVD_SLEEP_WITH_KEY if api_key else NVD_SLEEP_NO_KEY
    headers = {"apiKey": api_key} if api_key else None

    found: set[str] = set()
    cursor = start
    while cursor < end:
        window_end = min(cursor + timedelta(days=MAX_WINDOW_DAYS), end)
        start_index = 0
        while True:
            params = {
                "virtualMatchString": "cpe:2.3:*:oracle",
                "pubStartDate": cursor.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": NVD_PAGE_SIZE,
                "startIndex": start_index,
            }
            url = f"{NVD_ENDPOINT}?{urllib.parse.urlencode(params)}"
            print(f"NVD {cursor:%Y-%m-%d}..{window_end:%Y-%m-%d} offset {start_index}",
                  file=sys.stderr)

            payload = http_get_json(url, headers)
            page = payload.get("vulnerabilities", [])
            for item in page:
                cve_id = item.get("cve", {}).get("id")
                if cve_id:
                    found.add(cve_id)

            total = payload.get("totalResults", 0)
            start_index += NVD_PAGE_SIZE
            if start_index >= total or not page:
                break
            time.sleep(pause)

        cursor = window_end
        time.sleep(pause)

    print(f"  {len(found)} Oracle CVE IDs found", file=sys.stderr)
    return sorted(found)


# --------------------------------------------------------------------------
# Record parsing
# --------------------------------------------------------------------------

def cna_container(record: dict) -> dict:
    return record.get("containers", {}).get("cna", {})


def is_oracle(record: dict) -> bool:
    """True if Oracle assigned this CVE or is named as an affected vendor.

    Oracle assigns its own CVEs, so the assigner check covers a Critical Patch
    Update. The vendor check additionally catches records assigned by another
    CNA that still list an Oracle product as affected.
    """
    if record.get("cveMetadata", {}).get("assignerShortName", "").lower() == "oracle":
        return True
    for affected in cna_container(record).get("affected", []):
        if "oracle" in (affected.get("vendor") or "").lower():
            return True
    return False


def iter_cvss(record: dict):
    """Yield (cvss_data, source_label) for every CVSS block on the record.

    CVE Record v5 stores each score under a version-specific key such as
    `cvssV3_1`, and both the CNA and any ADP (a third party that enriches the
    record, for example CISA) may attach their own.
    """
    containers = record.get("containers", {})
    groups = [("CNA", containers.get("cna", {}))]
    groups += [("ADP", adp) for adp in containers.get("adp", [])]

    for label, container in groups:
        for metric in container.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if key in metric:
                    yield metric[key], label


def is_critical(record: dict) -> bool:
    """True if any scoring party rated this CVE CRITICAL.

    The vendor's own score is accepted because Oracle scores its CVEs at
    publication while NVD analysis can lag for months. For a tracker, missing a
    real critical is far worse than listing one a later analysis downgrades.
    """
    return any(
        data.get("baseSeverity", "").upper() == "CRITICAL"
        for data, _ in iter_cvss(record)
    )


def pick_cvss(record: dict) -> tuple[str, str, str, str]:
    """Return (score, severity, vector, source), preferring the highest score.

    Where the CNA and an enriching party disagree, showing the highest keeps the
    page conservative: a reader is never told an issue is milder than some
    recognised authority believes it to be.
    """
    best = None
    for data, label in iter_cvss(record):
        score = data.get("baseScore")
        if score is None:
            continue
        candidate = (
            float(score),
            data.get("baseSeverity", "UNKNOWN"),
            data.get("vectorString", "n/a"),
            label,
        )
        if best is None or candidate[0] > best[0]:
            best = candidate

    if best is None:
        return ("Not scored", "UNKNOWN", "n/a", "none")
    return (str(best[0]), best[1], best[2], best[3])


def english_description(record: dict) -> str:
    """Return the English description, tolerating locale tags like en-US."""
    descriptions = cna_container(record).get("descriptions", [])
    for entry in descriptions:
        if (entry.get("lang") or "").lower().startswith("en"):
            return (entry.get("value") or "").strip()
    if descriptions:
        return (descriptions[0].get("value") or "").strip()
    return "No description published for this record."


def affected_rows(record: dict) -> list[tuple[str, str]]:
    """Return (product, versions) pairs from the CNA's affected list.

    CVE Record v5 carries structured product and version data, which is far
    more precise than parsing a CPE string.
    """
    rows = []
    for affected in cna_container(record).get("affected", []):
        product = affected.get("product") or "Unspecified"
        versions = [
            v.get("version") for v in affected.get("versions", [])
            if v.get("status") == "affected" and v.get("version")
        ]
        rows.append((product, ", ".join(versions) if versions else "See advisory"))
    return rows


def weaknesses(record: dict) -> list[str]:
    """Return CWE classifications, the standard taxonomy for weakness types.

    Only entries carrying a real CWE identifier are returned. Some CNAs,
    Oracle among them, put narrative prose in this field that simply repeats
    the description, which would render as a duplicated paragraph.
    """
    found = []
    for problem in cna_container(record).get("problemTypes", []):
        for item in problem.get("descriptions", []):
            cwe_id = item.get("cweId")
            text = (item.get("description") or "").strip()

            if cwe_id:
                label = f"{cwe_id}: {text}" if text and not text.startswith(cwe_id) else (text or cwe_id)
            elif CWE_PATTERN.match(text):
                label = text
            else:
                continue  # Prose, not a classification.

            if label not in found:
                found.append(label)
    return found


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render_page(record: dict) -> str:
    meta = record.get("cveMetadata", {})
    cve_id = meta["cveId"]
    score, severity, vector, source = pick_cvss(record)
    published = (meta.get("datePublished") or "")[:10]
    updated = (meta.get("dateUpdated") or "")[:10]
    assigner = meta.get("assignerShortName", "unknown")

    lines = [
        f"# {cve_id}",
        "",
        f"Critical-severity vulnerability affecting Oracle products. "
        f"Published {published} by CNA `{assigner}`.",
        "",
        "## Severity",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| CVSS base score | {score} |",
        f"| Severity | {severity} |",
        f"| Vector | `{vector}` |",
        f"| Scored by | {source} |",
        f"| Published | {published} |",
        f"| Record updated | {updated} |",
        "",
        "## Description",
        "",
        english_description(record),
        "",
    ]

    cwes = weaknesses(record)
    if cwes:
        lines += ["## Weakness type", ""]
        lines += [f"- {cwe}" for cwe in cwes]
        lines.append("")

    rows = affected_rows(record)
    if rows:
        lines += [
            "## Affected products",
            "",
            "| Product | Affected versions |",
            "| --- | --- |",
        ]
        lines += [f"| {product} | {versions} |" for product, versions in rows[:30]]
        if len(rows) > 30:
            lines.append(f"| ...and {len(rows) - 30} more | See advisory |")
        lines.append("")

    lines += [
        "## Patches",
        "",
        "Oracle ships fixes in its quarterly Critical Patch Update. Patches are",
        "available from Oracle only:",
        "",
        f"- Oracle security alerts and CPU advisories: <{ORACLE_ADVISORY_URL}>",
        "- My Oracle Support, which requires a support contract: <https://support.oracle.com>",
        "",
        "This repository links to Oracle's advisories. It does not host, mirror or",
        "redistribute Oracle patch binaries.",
        "",
        "## References",
        "",
        f"- [CVE Record]({'https://www.cve.org/CVERecord?id=' + cve_id})",
        f"- [NVD entry](https://nvd.nist.gov/vuln/detail/{cve_id})",
    ]

    seen_urls = set()
    for reference in cna_container(record).get("references", []):
        url = reference.get("url")
        if url and url not in seen_urls:
            seen_urls.add(url)
            lines.append(f"- {url}")
        if len(seen_urls) >= 12:
            break

    lines += [
        "",
        "---",
        "",
        f"Tracked by [oracle-cve-tracker]({REPO_URL}), which follows critical-severity",
        "Oracle CVEs from the CVE Program's published records.",
        f"New entries are announced on [@oraclepdchannel]({CHANNEL_URL}), and",
        f"[@oraclepdbot]({BOT_URL}) searches this dataset and filters alerts by product.",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def tracked_ids(root: Path) -> set[str]:
    """Return every CVE ID that already has a folder in the repository."""
    found = set()
    for year_dir in root.glob("[0-9][0-9][0-9][0-9]"):
        if year_dir.is_dir():
            found.update(p.name for p in year_dir.iterdir() if p.is_dir())
    return found


def write_pages(records: list[dict], root: Path, force: bool) -> tuple[int, int]:
    """Write one folder per qualifying CVE. Returns (new, updated) counts."""
    new_count = updated_count = 0

    for record in records:
        meta = record.get("cveMetadata", {})
        cve_id = meta.get("cveId")
        if not cve_id or meta.get("state") == "REJECTED":
            continue
        if not is_oracle(record) or not is_critical(record):
            continue

        published = meta.get("datePublished") or ""
        year = published[:4] if published[:4].isdigit() else cve_id.split("-")[1]

        page_path = root / year / cve_id / "README.md"
        content = render_page(record)

        if page_path.exists():
            if not force and page_path.read_text(encoding="utf-8") == content:
                continue
            page_path.write_text(content, encoding="utf-8")
            updated_count += 1
        else:
            page_path.parent.mkdir(parents=True, exist_ok=True)
            page_path.write_text(content, encoding="utf-8")
            new_count += 1

    return new_count, updated_count


def write_index(root: Path) -> int:
    """Regenerate INDEX.md listing every tracked CVE, newest year first."""
    year_dirs = sorted(
        (p for p in root.glob("[0-9][0-9][0-9][0-9]") if p.is_dir()),
        key=lambda p: p.name,
        reverse=True,
    )

    lines = [
        "# Tracked CVEs",
        "",
        "Every critical-severity Oracle CVE this repository tracks, grouped by the",
        "year the record was published. Generated by `scripts/fetch_oracle_cves.py`.",
        "",
    ]
    total = 0
    for year_dir in year_dirs:
        entries = sorted((p.name for p in year_dir.iterdir() if p.is_dir()), reverse=True)
        if not entries:
            continue
        lines += [f"## {year_dir.name} ({len(entries)})", ""]
        lines += [f"- [{cve}]({year_dir.name}/{cve}/README.md)" for cve in entries]
        lines.append("")
        total += len(entries)

    (root / "INDEX.md").write_text("\n".join(lines), encoding="utf-8")
    return total


# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("delta", "backfill"), default="delta",
                        help="delta: recent CVE List changes (default). "
                             "backfill: historical range via NVD.")
    parser.add_argument("--days", type=int, default=2,
                        help="Delta mode: how many days of changes to read (default: 2).")
    parser.add_argument("--since", type=str,
                        help="Backfill mode: start date as YYYY-MM-DD.")
    parser.add_argument("--until", type=str,
                        help="Backfill mode: end date as YYYY-MM-DD (default: today).")
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).resolve().parent.parent,
                        help="Repository root to write CVE folders into.")
    parser.add_argument("--force", action="store_true",
                        help="Rewrite pages even when the content is unchanged.")
    args = parser.parse_args()

    root: Path = args.output
    root.mkdir(parents=True, exist_ok=True)

    try:
        if args.mode == "backfill":
            if not args.since:
                print("--since is required in backfill mode.", file=sys.stderr)
                return 2
            try:
                start = datetime.strptime(args.since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                end = (datetime.strptime(args.until, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                       if args.until else datetime.now(timezone.utc))
            except ValueError:
                print("Dates must be YYYY-MM-DD.", file=sys.stderr)
                return 2
            if start >= end:
                print("--since must be earlier than --until.", file=sys.stderr)
                return 2
            candidates = discover_from_nvd(start.replace(tzinfo=None), end.replace(tzinfo=None))
        else:
            candidates = discover_from_delta(args.days, tracked_ids(root))

        print(f"Fetching {len(candidates)} records from the CVE List", file=sys.stderr)
        records = fetch_records(candidates)

    except FetchError as exc:
        # Exit non-zero so CI fails loudly rather than committing nothing and
        # reporting success.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    new_count, updated_count = write_pages(records, root, args.force)
    total = write_index(root)

    print(f"Inspected {len(records)} records: {new_count} new, "
          f"{updated_count} updated, {total} tracked in total.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
