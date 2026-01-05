# ruff: noqa: I001
"""
Scrape public advisories/blogs for exploit chains and extract CVE groups.

This is a lightweight, dependency-minimal scraper that:
- Fetches a list of known pages where chained CVEs are documented.
- Extracts page title, CVE IDs, and chain-related indicators (keywords).
- Emits a structured JSON file under outputs/evaluations/gold/external_chains.json.

Usage:
  python -m sbom_toolkit.scripts.scrape_chains --output-base outputs
  python -m sbom_toolkit.scripts.scrape_chains --sources urls.txt --output-base outputs

Notes:
- No heavy HTML parsing: we strip tags and search text with regex.
- Extend SOURCES_DEFAULT with more URLs over time.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from typing import Any

import requests

from sbom_toolkit.shared.output import OutputManager


SOURCES_DEFAULT = [
    # Microsoft Exchange (ProxyLogon)
    "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/",
    # ProxyShell technical deep dives
    "https://www.trendmicro.com/en_us/research/21/h/proxyshell-a-technical-analysis-of-cve-2021-34473-cve-2021-34523-and-cve-2021-31207.html",
    # Ivanti Connect Secure chain (Volexity)
    "https://www.volexity.com/blog/2024/01/10/zero-day-exploited-in-ivanti-connect-secure/",
    # Ivanti advisory (CISA overview)
    "https://www.cisa.gov/news-events/alerts/2024/01/10/ivanti-connect-secure-and-policy-secure-vulnerabilities",
    # Juniper J-Web 2023 chain
    "https://supportportal.juniper.net/s/article/2023-08-17-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-may-allow-a-preAuth-remote-code-execution?language=en_US",
    # ConnectWise ScreenConnect 2024
    "https://www.rapid7.com/blog/post/2024/02/20/critical-screenconnect-authentication-bypass-and-path-traversal/",
    # Apple iOS BlastPass (Citizen Lab)
    "https://citizenlab.ca/2023/09/blastpass-iphone-zero-click-exploit/",
    # Apple iOS FORCEDENTRY (Citizen Lab)
    "https://citizenlab.ca/2021/09/forcedentry-nso-group-iphone-spyware/",
]


CVERE = re.compile(r"CVE-\d{4}-\d{4,7}")
CHAIN_TERMS = [
    r"\bchain(?:ed|ing)?\b",
    r"\bexploit chain\b",
    r"\bcombined\b",
    r"\bused together\b",
    r"\bin conjunction\b",
]
CHAIN_RE = re.compile("|".join(CHAIN_TERMS), flags=re.IGNORECASE)


@dataclass
class ChainCase:
    """Represents an extracted chain case from a source page."""

    source_url: str
    title: str | None
    cve_ids: list[str]
    chain_indicators: list[str]
    excerpt: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "title": self.title,
            "cve_ids": self.cve_ids,
            "chain_indicators": self.chain_indicators,
            "excerpt": self.excerpt,
        }


def _strip_html(html: str) -> str:
    # Remove scripts/styles crudely
    html = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.IGNORECASE)
    html = re.sub(r"<style[\s\S]*?</style>", " ", html, flags=re.IGNORECASE)
    # Remove tags
    text = re.sub(r"<[^>]+>", " ", html)
    text = unescape(text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _extract_title(html: str) -> str | None:
    m = re.search(r"<title>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if m:
        return unescape(m.group(1)).strip()
    return None


def _fetch(url: str, timeout: int = 20) -> tuple[str | None, str | None]:
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "sbom-toolkit/0.1"})
        if resp.status_code != 200:
            return None, None
        html = resp.text
        return html, _extract_title(html)
    except Exception:
        return None, None


def _extract_case(url: str) -> ChainCase | None:
    html, title = _fetch(url)
    if not html:
        return None
    text = _strip_html(html)
    cves = sorted(set(CVERE.findall(text)))
    indicators = CHAIN_RE.findall(text)
    # Pull an excerpt around the first chain term or first CVE occurrence
    excerpt = None
    anchor = None
    m = CHAIN_RE.search(text)
    if m:
        anchor = m.start()
    elif cves:
        m2 = re.search(re.escape(cves[0]), text)
        anchor = m2.start() if m2 else None
    if anchor is not None:
        start = max(0, anchor - 200)
        end = min(len(text), anchor + 200)
        excerpt = text[start:end]
    return ChainCase(
        source_url=url, title=title, cve_ids=cves, chain_indicators=indicators, excerpt=excerpt
    )


def scrape_sources(urls: list[str]) -> list[ChainCase]:
    cases: list[ChainCase] = []
    for url in urls:
        case = _extract_case(url)
        if case is not None and case.cve_ids:
            cases.append(case)
    return cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scrape exploit chains from known sources")
    parser.add_argument("--output-base", type=str, default="outputs", help="Base output dir")
    parser.add_argument(
        "--sources",
        type=str,
        default=None,
        help="Optional path to a file with URLs (one per line)",
    )
    args = parser.parse_args(argv)

    om = OutputManager(Path(args.output_base))
    gold_dir = om.base_dir / "evaluations" / "gold"
    gold_dir.mkdir(parents=True, exist_ok=True)
    out_path = gold_dir / "external_chains.json"

    urls: list[str] = []
    if args.sources:
        try:
            with open(args.sources, encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        urls.append(s)
        except Exception as e:
            print(f"Failed to read sources file: {e}")
            return 1
    else:
        urls = list(SOURCES_DEFAULT)

    cases = scrape_sources(urls)
    payload = {
        "source_count": len(urls),
        "cases_found": len(cases),
        "cases": [c.to_dict() for c in cases],
    }
    try:
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote {out_path}")
        print(f"Cases found: {len(cases)}")
    except Exception as e:
        print(f"Failed to write output: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
