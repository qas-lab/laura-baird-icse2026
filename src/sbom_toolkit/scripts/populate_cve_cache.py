"""
Populate CVE cache with data from NVD API.

Fetches CVE data for all CVEs referenced in attack chains and saves
them to the CVE cache directory.

Usage:
    python -m sbom_toolkit.scripts.populate_cve_cache --api-key YOUR_KEY
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import requests


def fetch_cve_from_nvd(cve_id: str, api_key: str | None = None) -> dict | None:
    """Fetch CVE data from NVD API v2.0.

    Args:
        cve_id: CVE identifier (e.g., CVE-2020-11651)
        api_key: Optional NVD API key for higher rate limits

    Returns:
        CVE data dictionary or None on failure
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "sbom-toolkit/0.1"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities and len(vulnerabilities) > 0:
                return vulnerabilities[0].get("cve")
        elif response.status_code == 404:
            print(f"  {cve_id}: Not found in NVD")
            return None
        else:
            print(f"  {cve_id}: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"  {cve_id}: Error - {e}")
        return None

    return None


def save_cve_to_cache(cve_id: str, cve_data: dict, cache_dir: Path) -> None:
    """Save CVE data to cache file.

    Args:
        cve_id: CVE identifier
        cve_data: CVE data from NVD
        cache_dir: Cache directory path
    """
    cache_file = cache_dir / f"{cve_id}.json"

    # Extract relevant fields
    cache_entry = {
        "id": cve_data.get("id", cve_id),
        "published": cve_data.get("published"),
        "lastModified": cve_data.get("lastModified"),
        "vulnStatus": cve_data.get("vulnStatus"),
        "descriptions": cve_data.get("descriptions", []),
        "metrics": cve_data.get("metrics", {}),
        "weaknesses": cve_data.get("weaknesses", []),
        "references": cve_data.get("references", []),
        "cached_at": time.time(),
    }

    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(cache_entry, f, indent=2)


def main(argv: list[str] | None = None) -> int:
    """Main function."""
    parser = argparse.ArgumentParser(description="Populate CVE cache from NVD API")
    parser.add_argument(
        "--api-key",
        type=str,
        required=True,
        help="NVD API key (get from https://nvd.nist.gov/developers/request-an-api-key)",
    )
    parser.add_argument(
        "--cache-dir",
        type=str,
        default="data/cve_cache",
        help="CVE cache directory",
    )
    parser.add_argument(
        "--external-chains",
        type=str,
        default="data/external_chains",
        help="Path to external chains file",
    )
    parser.add_argument(
        "--incidents",
        type=str,
        default="supply-chain-seeds/incidents.json",
        help="Path to incidents.json",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-fetch even if CVE exists in cache with full data",
    )

    args = parser.parse_args(argv)

    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Collect all CVE IDs
    cve_ids: set[str] = set()

    # From external chains
    external_chains_path = Path(args.external_chains)
    if external_chains_path.exists():
        try:
            with open(external_chains_path, encoding="utf-8") as f:
                data = json.load(f)
            for case in data.get("cases", []):
                cve_ids.update(case.get("cve_ids", []))
            print(f"Loaded {len(cve_ids)} CVEs from external_chains")
        except Exception as e:
            print(f"Warning: Could not load external_chains: {e}")

    # From incidents
    incidents_path = Path(args.incidents)
    if incidents_path.exists():
        try:
            with open(incidents_path, encoding="utf-8") as f:
                data = json.load(f)
            for incident in data:
                cve_ids.update(incident.get("cves", []))
            print(f"Total {len(cve_ids)} unique CVEs to fetch")
        except Exception as e:
            print(f"Warning: Could not load incidents: {e}")

    if not cve_ids:
        print("No CVEs found to fetch")
        return 1

    # Check which CVEs need fetching
    to_fetch = []
    for cve_id in sorted(cve_ids):
        cache_file = cache_dir / f"{cve_id}.json"
        if args.force or not cache_file.exists():
            to_fetch.append(cve_id)
        else:
            # Check if it's a stub file (only has cve_id and cwes)
            try:
                with open(cache_file, encoding="utf-8") as f:
                    cached = json.load(f)
                if "metrics" not in cached or not cached.get("metrics"):
                    to_fetch.append(cve_id)
            except Exception:
                to_fetch.append(cve_id)

    print(f"\nNeed to fetch: {len(to_fetch)} CVEs")
    print(f"Already cached: {len(cve_ids) - len(to_fetch)} CVEs")

    if not to_fetch:
        print("All CVEs are already cached!")
        return 0

    print("\nFetching CVE data from NVD API...")
    print("(Rate limit: 50 requests per 30 seconds with API key)")

    # Fetch CVEs with rate limiting
    fetched = 0
    failed = 0
    start_time = time.time()

    for i, cve_id in enumerate(to_fetch, 1):
        print(f"[{i}/{len(to_fetch)}] {cve_id}...", end=" ")

        cve_data = fetch_cve_from_nvd(cve_id, args.api_key)

        if cve_data:
            save_cve_to_cache(cve_id, cve_data, cache_dir)
            print("✓")
            fetched += 1
        else:
            print("✗")
            failed += 1

        # Rate limiting: 50 requests per 30 seconds with API key
        # Be conservative: 40 requests per 30 seconds = 0.75s per request
        if i < len(to_fetch):
            time.sleep(0.75)

    elapsed = time.time() - start_time
    print(f"\nCompleted in {elapsed:.1f}s")
    print(f"  Fetched: {fetched}")
    print(f"  Failed: {failed}")
    print(f"  Cache directory: {cache_dir.absolute()}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
