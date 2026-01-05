"""
Gold evaluation set builder for HGAT MVP.

This script:
- Loads a list of seed repositories (GitHub URLs)
- Generates SBOMs (organized under outputs/)
- Scans SBOMs with grype to embed vulnerability data
- Builds a selective knowledge graph (CWE/CAPEC for present CVEs)
- Emits per-repo annotation data with candidate vulnerable dependency pairs

Outputs are written under outputs/evaluations/gold/{slug}/

Seed file formats supported:
- JSON array: [{"repository_url": "https://github.com/owner/repo", "incident_id": "AC-123", ...}, ...]
- Plain text: one GitHub URL per line (lines starting with '#' ignored)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..pipeline.sbom.generation import SBOMProcessor
from ..pipeline.security.scanning import process_single_sbom
from ..shared.models import ProcessingConfig
from ..shared.output import OutputManager


@dataclass
class SeedItem:
    repository_url: str
    incident_id: str | None = None
    notes: str | None = None


def _load_seeds(seeds_path: Path) -> list[SeedItem]:
    """Load seed repositories from JSON array or plaintext file."""
    if not seeds_path.exists():
        raise FileNotFoundError(f"Seeds file not found: {seeds_path}")

    if seeds_path.suffix.lower() == ".json":
        with open(seeds_path, encoding="utf-8") as f:
            data = json.load(f)
        seeds: list[SeedItem] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            url = entry.get("repository_url")
            if not url:
                continue
            seeds.append(
                SeedItem(
                    repository_url=str(url),
                    incident_id=str(entry["incident_id"]) if entry.get("incident_id") else None,
                    notes=str(entry["notes"]) if entry.get("notes") else None,
                )
            )
        return seeds

    # Fallback: plaintext, one URL per non-comment line
    seeds = []
    with open(seeds_path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            seeds.append(SeedItem(repository_url=stripped))
    return seeds


def _component_key(component: dict[str, Any]) -> str:
    """Derive a stable component key (prefer purl, else bom-ref, else name@version)."""
    if "purl" in component and component["purl"]:
        return str(component["purl"])
    if "bom-ref" in component and component["bom-ref"]:
        return str(component["bom-ref"])
    name = component.get("name", "unknown")
    version = component.get("version", "unknown")
    return f"{name}@{version}"


def _extract_candidate_pairs(enriched_sbom: dict[str, Any]) -> dict[str, Any]:
    """Produce candidate vulnerable dependency pairs to speed up manual labeling.

    A pair (A -> B) is included if there is a dependency edge and both components
    have at least one vulnerability. Basic features included for ranking/triage.
    """
    components = enriched_sbom.get("components", [])
    dependencies = enriched_sbom.get("dependencies", [])

    comp_by_key: dict[str, dict[str, Any]] = {}
    for comp in components:
        key = _component_key(comp)
        comp_by_key[key] = comp

    def _vuln_stats(comp: dict[str, Any]) -> tuple[int, float, float, bool, list[dict[str, Any]]]:
        vulns = comp.get("vulnerabilities", [])
        if not vulns:
            return 0, 0.0, 0.0, False, []
        scores = [v.get("cvss_score") for v in vulns if v.get("cvss_score") is not None]
        count = len(vulns)
        max_score = float(max(scores)) if scores else 0.0
        avg_score = float(sum(scores) / len(scores)) if scores else 0.0
        has_critical = any((v.get("cvss_severity") == "CRITICAL") for v in vulns)
        return count, max_score, avg_score, has_critical, vulns

    def _cwe_set(vulns: list[dict[str, Any]]) -> set[str]:
        cwes: set[str] = set()
        for v in vulns:
            for c in v.get("cwe_ids", []) or []:
                cwes.add(str(c))
        return cwes

    pairs: list[dict[str, Any]] = []
    edges_seen: set[tuple[str, str]] = set()

    for dep in dependencies:
        source = dep.get("ref")
        targets = dep.get("dependsOn", [])
        if not source or not isinstance(targets, list):
            continue
        for target in targets:
            a = comp_by_key.get(source)
            b = comp_by_key.get(target)
            if a is None or b is None:
                continue
            if (source, target) in edges_seen:
                continue
            edges_seen.add((source, target))

            a_count, a_max, a_avg, a_crit, a_vulns = _vuln_stats(a)
            b_count, b_max, b_avg, b_crit, b_vulns = _vuln_stats(b)
            if a_count == 0 or b_count == 0:
                continue

            a_cwe = _cwe_set(a_vulns)
            b_cwe = _cwe_set(b_vulns)
            shared_cwe = sorted(a_cwe.intersection(b_cwe))

            # Simple triage score for ranking: max CVSS focus and CWE overlap bonus
            score = (0.45 * a_max) + (0.45 * b_max) + (0.1 * (1.0 if shared_cwe else 0.0))

            pairs.append(
                {
                    "source": source,
                    "target": target,
                    "source_summary": {
                        "vuln_count": a_count,
                        "max_cvss": a_max,
                        "avg_cvss": a_avg,
                        "has_critical": a_crit,
                    },
                    "target_summary": {
                        "vuln_count": b_count,
                        "max_cvss": b_max,
                        "avg_cvss": b_avg,
                        "has_critical": b_crit,
                    },
                    "shared_cwe": shared_cwe,
                    "triage_score": round(score, 3),
                    "label": None,  # to be filled by human: "chain" | "no_chain" | "unknown"
                }
            )

    # Sort pairs by triage score descending
    pairs.sort(key=lambda p: p.get("triage_score", 0.0), reverse=True)
    return {"candidate_pairs": pairs}


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def build_gold_from_seeds(seeds_path: Path, output_base: Path, no_cache: bool = False) -> None:
    """Run pipeline over seeds and emit per-repo gold annotation packs."""
    output_manager = OutputManager(output_base)
    seeds = _load_seeds(seeds_path)

    if not seeds:
        print("No seeds to process.")
        return

    config = ProcessingConfig(output_dir=output_manager.base_dir, cache_enabled=not no_cache)

    for seed in seeds:
        repo_url = seed.repository_url
        print(f"Processing: {repo_url}")

        try:
            with SBOMProcessor(config, repo_cache_enabled=not no_cache) as sbom_proc:
                sbom_path = sbom_proc.process_repository(repo_url)

            # Enrich with grype
            enriched_sbom_path = output_manager.get_scan_path(sbom_path, "grype", no_cache=no_cache)
            success = process_single_sbom(sbom_path, enriched_sbom_path, cache_enabled=not no_cache)
            if not success:
                print(f"Failed to enrich SBOM for {repo_url}")
                continue

            # Load enriched data
            with open(enriched_sbom_path, encoding="utf-8") as f:
                enriched_data = json.load(f)

            # Build KG (selective CWE/CAPEC enhancement)
            try:
                from ..intelligence.graph.builder import KnowledgeGraphBuilder

                kg_builder = KnowledgeGraphBuilder()
                repo_slug = output_manager.clean_repo_name(repo_url)
                sbom_id = f"sbom_{repo_slug}"
                kg_builder.build_from_sbom_data(enriched_data, sbom_id)
                try:
                    kg_builder.build_selective_cwe_capec_from_sbom(enriched_data)
                except Exception:
                    # Continue without CWE/CAPEC enrichment
                    pass
                kg_data = kg_builder.get_graph_data()
            except Exception as e:
                print(f"KG build failed for {repo_url}: {e}")
                kg_data = {"nodes": [], "edges": []}

            # Prepare evaluation pack directory
            repo_slug = output_manager.clean_repo_name(repo_url)
            eval_dir = output_manager.base_dir / "evaluations" / "gold" / repo_slug
            _ensure_dir(eval_dir)

            # Save assets
            with open(eval_dir / "enriched_sbom.json", "w", encoding="utf-8") as f:
                json.dump(enriched_data, f, indent=2)
            with open(eval_dir / "knowledge_graph.json", "w", encoding="utf-8") as f:
                json.dump(kg_data, f, indent=2)

            # Emit component catalog for quick reference
            components = enriched_data.get("components", [])
            comp_catalog = []
            for comp in components:
                comp_catalog.append(
                    {
                        "key": _component_key(comp),
                        "name": comp.get("name"),
                        "version": comp.get("version"),
                        "purl": comp.get("purl"),
                        "vulnerability_count": len(comp.get("vulnerabilities", [])),
                    }
                )
            with open(eval_dir / "components.json", "w", encoding="utf-8") as f:
                json.dump({"components": comp_catalog}, f, indent=2)

            # Emit candidate pairs for annotation
            candidates = _extract_candidate_pairs(enriched_data)
            with open(eval_dir / "candidate_pairs.json", "w", encoding="utf-8") as f:
                json.dump(candidates, f, indent=2)

            # Annotation template metadata
            template = {
                "repository_url": repo_url,
                "incident_id": seed.incident_id,
                "notes": seed.notes,
                "instructions": (
                    "Label candidate_pairs entries as 'chain' or 'no_chain'. "
                    "A 'chain' should reflect a plausible exploit step between dependent components."
                ),
            }
            with open(eval_dir / "annotation_template.json", "w", encoding="utf-8") as f:
                json.dump(template, f, indent=2)

            print(f"✓ Wrote gold pack: {eval_dir}")

        except Exception as e:
            print(f"Unexpected error processing {repo_url}: {e}")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build gold eval packs from seed repositories")
    parser.add_argument("seeds", type=str, help="Path to seeds file (.json array or .txt list)")
    parser.add_argument(
        "--output-base",
        "-o",
        type=str,
        default="outputs",
        help="Base output directory (organized subdirs will be created)",
    )
    parser.add_argument("--no-cache", action="store_true", help="Disable caching")

    args = parser.parse_args()
    try:
        build_gold_from_seeds(
            Path(args.seeds), Path(args.output_base), no_cache=bool(args.no_cache)
        )
    except Exception as e:
        print(f"Failed to build gold eval set: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
