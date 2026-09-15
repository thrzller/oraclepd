# Oracle CVE Tracker

Critical-severity vulnerabilities in Oracle products, collected automatically
from the CVE Program's published records and kept as one readable page per CVE.

Oracle publishes several hundred CVEs in each quarterly Critical Patch Update.
Finding the ones that actually matter to your estate means reading a large
advisory matrix every quarter. This repository does that filtering once, in the
open, so you can watch a folder instead.

## Telegram alerts

Two companions to this repository, for people who would rather be told than go
looking:

| | |
| --- | --- |
| [@oraclepdchannel](https://t.me/oraclepdchannel) | Posts an alert when a new critical Oracle CVE is published, with the score and a link to Oracle's advisory. |
| [@oraclepdbot](https://t.me/oraclepdbot) | Searches this dataset and filters alerts down to the Oracle products you actually run. |

**On patches.** The channel and bot send notifications and links. They do not
distribute Oracle patch binaries, and neither does this repository. Oracle ships
fixes only through [My Oracle Support](https://support.oracle.com) under a
support contract, and its advisories live at
[oracle.com/security-alerts](https://www.oracle.com/security-alerts/). Treat any
source offering Oracle patches outside those two channels as untrusted.

## Layout

```
2026/
  CVE-2026-35290/
    README.md
  CVE-2026-46876/
    README.md
INDEX.md            every tracked CVE, newest year first
scripts/
  fetch_oracle_cves.py
```

Each CVE page carries the CVSS score and vector with the party that assigned it,
the description as published, the affected products and versions, and links to
Oracle's advisory, the CVE Record and the NVD entry.

Start at [INDEX.md](INDEX.md).

## Where the data comes from

The authoritative source is the CVE Program's
[CVE List V5](https://github.com/CVEProject/cvelistV5), which stores each record
exactly as the assigning authority wrote it. Oracle is itself a CNA, the
organisation authorised to assign CVE IDs for its own products, so its severity
scores appear the moment a patch update ships.

Discovery runs in two modes:

- **delta** reads the CVE List's rolling change log for records published or
  updated in the last couple of days. This is the daily path, and it sees a new
  Oracle CVE within the hour.
- **backfill** enumerates a historical date range through the
  [NVD API](https://nvd.nist.gov/developers/vulnerabilities), which can filter by
  CPE vendor server-side. This is how the repository was first populated.

### Why severity is filtered locally

The NVD API accepts a `cvssV3Severity=CRITICAL` parameter, and using it would be
the obvious shortcut. It is also wrong for this purpose.

That filter matches only NVD's own analysis, and NVD has a large enrichment
backlog. Of the 1,108 Oracle CVEs published in July 2026, every one carried a
score from Oracle, but only four had been scored by NVD:

| Scoring source | Records | Rated critical |
| --- | --- | --- |
| Oracle (the CNA) | 1,108 | 210 |
| NVD | 4 | 1 |

Filtering server-side would have tracked **1** critical CVE where **211** were
genuinely critical. So the tracker fetches the full record and decides severity
from every score attached to it, accepting the vendor's own rating. For a
tracker, missing a real critical is far worse than listing one a later analysis
downgrades.

## Running it yourself

The script uses only the Python standard library, so there is nothing to
install and no dependency supply chain to audit. Python 3.10 or newer.

```bash
# Recent changes, the daily path
python3 scripts/fetch_oracle_cves.py --mode delta --days 2

# Populate history for a date range
python3 scripts/fetch_oracle_cves.py --mode backfill --since 2026-01-01

# Point generated links at your own fork
TRACKER_REPO=your-name/oracle-cve-tracker \
  python3 scripts/fetch_oracle_cves.py --mode delta --force
```

An [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) is optional
and only affects backfill speed, raising the rate limit from 5 to 50 requests per
30 seconds. Pass it as the `NVD_API_KEY` environment variable, and in CI store it
as a repository secret rather than committing it.

## Automation

[`.github/workflows/update-cves.yml`](.github/workflows/update-cves.yml) runs
daily, writes any new or changed pages and commits them. You can also trigger it
by hand from the Actions tab to run a backfill over a chosen date range.

## Accuracy

Pages are generated from published records and inherit any error in them. The
CVE Record and NVD entry linked at the bottom of every page are the sources of
truth. If a page looks wrong, please open an issue.

## Licence

Tracker code and generated pages: MIT. The underlying CVE records are published
by the CVE Program under
[its own terms](https://www.cve.org/Legal/TermsOfUse).
