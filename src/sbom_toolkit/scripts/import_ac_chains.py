# ruff: noqa: I001
"""
Import Atlantic Council software supply chain dataset and generate gold packs.

This script parses the dataset (CSV or JSON), extracts incidents with 2+ CVEs
that indicate potential exploit chains, then scans existing enriched SBOMs to
find component pairs connected by a dependency edge where each endpoint has a
case CVE. For each SBOM with matches, it emits a gold pack under
outputs/evaluations/gold/ac_<sbom-stem>/ with:

- enriched_sbom.json (copied from scan)
- candidate_pairs.json (entries labeled "chain")

Usage examples:
  python -m sbom_toolkit.scripts.import_ac_chains --dataset data/ac_dataset/dataset.csv \
      --output-base outputs
  python -m sbom_toolkit.scripts.import_ac_chains --dataset ac_data/cases.json \
      --scan-dir outputs/scans --output-base outputs
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sbom_toolkit.shared.output import OutputManager


CVERE = re.compile(r"CVE-\d{4}-\d{4,7}")


@dataclass
class ChainCase:
    """Minimal representation of an incident containing 2+ CVEs."""

    title: str
    cves: list[str]
    refs: list[str]


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


def _parse_cases_from_csv(path: Path) -> list[ChainCase]:
    # Aggregate by likely incident grouping fields
    groups: dict[str, dict[str, Any]] = {}
    try:
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                # Determine group key
                name = None
                for key in ("Name", "name", "Title", "title", "Incident", "incident"):
                    if key in row and row[key]:
                        name = str(row[key])
                        break
                group_key = name or f"row_{i}"
                g = groups.setdefault(group_key, {"title": name, "cves": set(), "refs": set()})

                # Scan fields for CVEs and refs
                for _k, v in row.items():
                    if v is None:
                        continue
                    s = str(v)
                    for c in CVERE.findall(s):
                        g["cves"].add(c)
                    if "http" in s:
                        for tok in s.split():
                            if tok.startswith("http"):
                                g["refs"].add(tok)
    except Exception:
        return []

    cases: list[ChainCase] = []
    for key, g in groups.items():
        cves = sorted(g["cves"])  # type: ignore[arg-type]
        if len(cves) >= 2:
            cases.append(ChainCase(title=g.get("title") or key, cves=cves, refs=sorted(g["refs"])))
    return cases


def _parse_cases_from_json(path: Path) -> list[ChainCase]:
    content = _read_text(path)
    if content is None:
        return []
    try:
        data = json.loads(content)
    except Exception:
        return []
    cases: list[ChainCase] = []
    # Accept either list[dict] or dict with items
    rows: list[dict[str, Any]]
    if isinstance(data, list):
        rows = [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        rows = [data]
    else:
        return []
    # Group by title/name-like fields
    groups: dict[str, dict[str, Any]] = {}
    for i, row in enumerate(rows):
        name = None
        for key in ("title", "name", "incident", "case"):
            if key in row and row[key]:
                name = str(row[key])
                break
        key = name or f"item_{i}"
        g = groups.setdefault(key, {"title": name, "cves": set(), "refs": set()})
        for _k, v in row.items():
            if v is None:
                continue
            s = str(v)
            for c in CVERE.findall(s):
                g["cves"].add(c)
            if "http" in s:
                for tok in s.split():
                    if tok.startswith("http"):
                        g["refs"].add(tok)
    for key, g in groups.items():
        cves = sorted(g["cves"])  # type: ignore[arg-type]
        if len(cves) >= 2:
            cases.append(ChainCase(title=g.get("title") or key, cves=cves, refs=sorted(g["refs"])))
    return cases


def _load_ac_cases(dataset_path: Path) -> list[ChainCase]:
    suffix = dataset_path.suffix.lower()
    if suffix in (".csv", ".tsv"):
        return _parse_cases_from_csv(dataset_path)
    if suffix in (".json", ".ndjson"):
        return _parse_cases_from_json(dataset_path)
    # Try CSV by default
    return _parse_cases_from_csv(dataset_path)


def _component_key(comp: dict[str, Any]) -> str:
    if comp.get("purl"):
        return str(comp["purl"])
    if comp.get("bom-ref"):
        return str(comp["bom-ref"])
    return f"{comp.get('name', 'unknown')}@{comp.get('version', 'unknown')}"


def _build_cve_index(sbom: dict[str, Any]) -> dict[str, set[str]]:
    """Map CVE -> set(component_key) in this SBOM."""
    idx: dict[str, set[str]] = {}
    for comp in sbom.get("components", []) or []:
        ck = _component_key(comp)
        for v in comp.get("vulnerabilities", []) or []:
            cve = v.get("cve_id") or v.get("id") or v.get("source_id")
            if not cve:
                continue
            cve_s = str(cve)
            if not CVERE.fullmatch(cve_s):
                continue
            idx.setdefault(cve_s, set()).add(ck)
    return idx


def _dependency_edges(sbom: dict[str, Any]) -> set[tuple[str, str]]:
    edges: set[tuple[str, str]] = set()
    for dep in sbom.get("dependencies", []) or []:
        src = dep.get("ref")
        tgts = dep.get("dependsOn", []) or []
        if not isinstance(src, str):
            continue
        for t in tgts:
            if not isinstance(t, str):
                continue
            edges.add((src, t))
            edges.add((t, src))  # treat as undirected for candidate search
    return edges


def _find_chain_pairs(sbom: dict[str, Any], cases: list[ChainCase]) -> list[dict[str, Any]]:
    cve_to_components = _build_cve_index(sbom)
    edges = _dependency_edges(sbom)
    pairs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for case in cases:
        present = [c for c in case.cves if c in cve_to_components]
        if len(present) < 2:
            continue
        # For each pair of CVEs in the case, look for component pairs connected by an edge
        comps_by_cve = [cve_to_components[c] for c in present]
        # Flatten to candidate components with any case CVE
        comps = sorted(set().union(*comps_by_cve))
        for i, a in enumerate(comps):
            for b in comps[i + 1 :]:
                if (a, b) in seen or (b, a) in seen:
                    continue
                if (a, b) not in edges and (b, a) not in edges:
                    continue
                # Gather basic stats
                pairs.append(
                    {
                        "source": a,
                        "target": b,
                        "label": "chain",
                        "source_case_cves": sorted(
                            [c for c in present if a in cve_to_components.get(c, set())]
                        ),
                        "target_case_cves": sorted(
                            [c for c in present if b in cve_to_components.get(c, set())]
                        ),
                        "refs": case.refs[:5],
                        "case_title": case.title,
                    }
                )
                seen.add((a, b))
    return pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import AC dataset and build chain gold packs")
    parser.add_argument("--dataset", type=str, required=True, help="Path to AC dataset (CSV/JSON)")
    parser.add_argument("--output-base", type=str, default="outputs", help="Base output dir")
    parser.add_argument(
        "--scan-dir",
        type=str,
        default=None,
        help="Override enriched scans directory (defaults to OutputManager().dirs['scans'])",
    )
    args = parser.parse_args(argv)

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}")
        return 1

    om = OutputManager(Path(args.output_base))
    scan_dir = Path(args.scan_dir) if args.scan_dir else om.dirs["scans"]
    gold_root = om.base_dir / "evaluations" / "gold"
    gold_root.mkdir(parents=True, exist_ok=True)

    cases = _load_ac_cases(dataset_path)
    print(f"Loaded {len(cases)} chain cases from dataset")
    if not cases:
        return 0

    # Iterate scans and build packs when matches exist
    created = 0
    for scan_path in sorted(scan_dir.glob("*.json")):
        try:
            with scan_path.open(encoding="utf-8") as fh:
                sbom = json.load(fh)
        except Exception:
            continue
        pairs = _find_chain_pairs(sbom, cases)
        if not pairs:
            continue
        slug = "ac_" + scan_path.stem
        pack_dir = gold_root / slug
        pack_dir.mkdir(parents=True, exist_ok=True)
        # Save SBOM copy
        try:
            with (pack_dir / "enriched_sbom.json").open("w", encoding="utf-8") as f:
                json.dump(sbom, f, indent=2)
        except Exception:
            pass
        # Save candidate pairs
        with (pack_dir / "candidate_pairs.json").open("w", encoding="utf-8") as f:
            json.dump({"candidate_pairs": pairs}, f, indent=2)
        created += 1
        print(f"Created gold pack {slug} with {len(pairs)} chain pairs")

    print(f"Total gold packs created: {created}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
