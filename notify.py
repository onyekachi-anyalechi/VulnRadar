#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

DEFAULT_TIMEOUT = (10, 60)


def _session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "User-Agent": "VulnRadar-Notify/0.1",
            "Authorization": f"Bearer {token}",
        }
    )
    return s


def _load_items(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return payload["items"]
    if isinstance(payload, list):
        return payload
    return []


def _search_issue_exists(session: requests.Session, repo: str, cve_id: str) -> bool:
    # Search across open/closed issues to avoid duplicates.
    q = f'repo:{repo} in:title "{cve_id}" "[VulnRadar]"'
    url = "https://api.github.com/search/issues"
    r = session.get(url, params={"q": q, "per_page": 1}, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    return int(data.get("total_count") or 0) > 0


def _create_issue(session: requests.Session, repo: str, title: str, body: str, labels: Optional[List[str]] = None) -> None:
    url = f"https://api.github.com/repos/{repo}/issues"
    payload: Dict[str, Any] = {"title": title, "body": body}
    if labels:
        payload["labels"] = labels
    r = session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def _issue_body(item: Dict[str, Any]) -> str:
    cve_id = str(item.get("cve_id") or "")
    desc = str(item.get("description") or "").strip()
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    kev = bool(item.get("active_threat"))
    patch = bool(item.get("in_patchthis"))
    watch = bool(item.get("watchlist_hit"))
    priority = str(item.get("priority_label") or "").strip()

    def fmt(x: Any, ndigits: int) -> str:
        try:
            return f"{float(x):.{ndigits}f}"
        except Exception:
            return ""

    lines = []
    lines.append(f"CVE: {cve_id}")
    lines.append(f"Priority: {priority}" if priority else "Priority: (none)")
    lines.append("")
    lines.append("Signals:")
    lines.append(f"- PatchThis: {'yes' if patch else 'no'}")
    lines.append(f"- Watchlist: {'yes' if watch else 'no'}")
    lines.append(f"- CISA KEV: {'yes' if kev else 'no'}")
    lines.append(f"- EPSS: {fmt(epss, 3)}")
    lines.append(f"- CVSS: {fmt(cvss, 1)}")
    lines.append("")
    if desc:
        lines.append("Description:")
        lines.append(desc)
        lines.append("")
    lines.append(f"CVE.org record: https://www.cve.org/CVERecord?id={cve_id}")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description="VulnRadar notifications (GitHub Issues)")
    p.add_argument("--in", dest="inp", default="data/radar_data.json", help="Path to radar_data.json")
    p.add_argument("--max", dest="max_items", type=int, default=25, help="Max issues to create per run")
    p.add_argument(
        "--include-warnings",
        action="store_true",
        help="Also notify on PatchThis WARNING (shadow IT) items",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print would-notify CVEs without creating issues",
    )
    args = p.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise SystemExit("GITHUB_REPOSITORY is required")
    if not token:
        raise SystemExit("GITHUB_TOKEN (or GH_TOKEN) is required")

    items = _load_items(Path(args.inp))

    # Notify policy:
    # - Always notify on CRITICAL PatchThis+Watchlist
    # - Optionally notify on PatchThis WARNING
    candidates: List[Dict[str, Any]] = []
    for it in items:
        label = str(it.get("priority_label") or "")
        if label.startswith("CRITICAL"):
            candidates.append(it)
        elif args.include_warnings and label.startswith("WARNING"):
            candidates.append(it)

    # Sort to notify highest first
    def key(it: Dict[str, Any]) -> float:
        try:
            return float(it.get("probability_score") or 0.0)
        except Exception:
            return 0.0

    candidates = sorted(candidates, key=key, reverse=True)

    session = _session(token)
    created = 0
    for it in candidates:
        if created >= args.max_items:
            break
        cve_id = str(it.get("cve_id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue

        if _search_issue_exists(session, repo, cve_id):
            continue

        priority = str(it.get("priority_label") or "").strip() or "ALERT"
        title = f"[VulnRadar] {priority}: {cve_id}"
        body = _issue_body(it)
        labels = ["vulnradar", "alert"]
        if str(it.get("priority_label") or "").startswith("CRITICAL"):
            labels.append("critical")

        if args.dry_run:
            print(f"DRY RUN: would create issue: {title}")
            created += 1
            continue

        _create_issue(session, repo, title=title, body=body, labels=labels)
        print(f"Created issue for {cve_id}")
        created += 1

    print(f"Done. Created {created} issues.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
