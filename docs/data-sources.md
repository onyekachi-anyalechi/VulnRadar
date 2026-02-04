# Data Sources

## CVE List V5 (CVEProject/cvelistV5)

- Uses the GitHub Releases API to locate the latest asset ending in `_all_CVEs_at_midnight.zip`.
- No NVD API is used.

## CISA KEV

- JSON feed: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>

## EPSS

- Daily CSV (gz): <https://epss.empiricalsecurity.com/epss_scores-current.csv.gz>

## PatchThis

- PatchThis intelligence CSV: <https://raw.githubusercontent.com/RogoLabs/patchthisapp/main/web/data.csv>

## Verify

- Confirm URLs are reachable
- Confirm ETL succeeds without manual downloads
