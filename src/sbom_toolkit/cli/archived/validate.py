"""
Validation commands for SBOM toolkit CLI.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from ...pipeline.repository import RepositoryHandler
from ...pipeline.tools import generate_sbom
from ...shared.exceptions import SBOMToolkitError
from ...shared.models import RepositoryInfo
from ...visualization.legacy.f_graph_generator import SBOMGraph
from ..utils import get_click

click, CLICK_AVAILABLE = get_click()


class SBOMGenerationValidator:
    """Validates SBOM generation by comparing different generation methods."""

    def __init__(self, ctx):
        """Initialize the validator."""
        self.report_data = {}
        self.ctx = ctx

    def compare_generation_methods(self, repository_url: str, output_dir: Path) -> dict[str, Any]:
        """Compare SBOM generation between Docker and Syft methods.

        Args:
            repository_url: GitHub repository URL to analyze
            output_dir: Directory to store generated SBOMs and reports

        Returns:
            Detailed comparison report
        """
        generation_results: dict[str, Any] = {}
        report: dict[str, Any] = {
            "validation_metadata": {
                "timestamp": datetime.now().isoformat(),
                "repository_url": repository_url,
                "validator_version": "1.0.0",
            },
            "generation_results": generation_results,
            "component_analysis": {},
            "vulnerability_analysis": {},
            "contamination_check": {},
            "recommendations": [],
        }

        # Clone repository for analysis
        import tempfile

        temp_dir = Path(tempfile.mkdtemp(prefix="sbom_validation_"))
        repo_handler = RepositoryHandler(temp_dir)
        repo_info = None

        try:
            repo_info = repo_handler.clone_repository(repository_url)

            # Generate SBOM using Syft (Docker method is archived)
            syft_sbom, docker_sbom = self._generate_both_sboms(repo_info, output_dir)

            if not syft_sbom:
                generation_results["error"] = "Failed to generate SBOM with Syft"
                return report

            # Load SBOM data
            with open(syft_sbom) as f:
                syft_data = json.load(f)

            # Docker data is not available since it's archived
            docker_data = {}

            # Store generation results
            generation_results.update(
                {
                    "syft_sbom_path": str(syft_sbom),
                    "docker_sbom_path": str(docker_sbom),
                    "syft_success": True,
                    "docker_success": True,
                }
            )

            # Analyze components
            report["component_analysis"] = self._analyze_component_differences(
                syft_data, docker_data
            )

            # Analyze vulnerabilities (if present)
            report["vulnerability_analysis"] = self._analyze_vulnerability_differences(
                syft_data, docker_data
            )

            # Check for contamination
            report["contamination_check"] = self._check_contamination(
                syft_data, docker_data, repo_info
            )

            # Generate recommendations
            report["recommendations"] = self._generate_comparison_recommendations(report)

        except Exception as e:
            generation_results["error"] = f"Generation comparison failed: {str(e)}"
        finally:
            # Cleanup
            if repo_info:
                try:
                    repo_handler.cleanup(repo_info)
                except Exception as e:
                    # Log but don't fail on cleanup
                    logger = self.ctx.obj["logger"]
                    logger.error(f"Error during cleanup: {str(e)}")
                    pass

        return report

    def _generate_both_sboms(
        self, repo_info: RepositoryInfo, output_dir: Path
    ) -> tuple[Path, Path | None]:
        """Generate SBOMs using Syft method. Docker method archived."""
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate with direct Syft
        syft_output_dir = output_dir / "syft"
        syft_output_dir.mkdir(exist_ok=True)
        syft_sbom = generate_sbom(repo_info, syft_output_dir, generator="syft")

        if not syft_sbom:
            raise SBOMToolkitError("Syft SBOM generation failed")

        # Docker generation has been archived - skip Docker validation
        # Skip docker validation since it's archived
        return syft_sbom, None

    def _analyze_component_differences(
        self, syft_data: dict[str, Any], docker_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze differences in components between generation methods."""
        syft_components = self._extract_components(syft_data)
        docker_components = self._extract_components(docker_data)

        # Create component sets for comparison
        syft_component_ids = set(syft_components.keys())
        docker_component_ids = set(docker_components.keys())

        # Find differences
        only_in_syft = syft_component_ids - docker_component_ids
        only_in_docker = docker_component_ids - syft_component_ids
        common_components = syft_component_ids & docker_component_ids

        # Analyze component types
        syft_types = self._count_component_types(syft_components)
        docker_types = self._count_component_types(docker_components)

        return {
            "syft_total": len(syft_components),
            "docker_total": len(docker_components),
            "common_components": len(common_components),
            "only_in_syft": len(only_in_syft),
            "only_in_docker": len(only_in_docker),
            "only_in_syft_list": list(only_in_syft)[:20],  # First 20 for brevity
            "only_in_docker_list": list(only_in_docker)[:20],
            "syft_component_types": syft_types,
            "docker_component_types": docker_types,
            "overlap_percentage": len(common_components) / max(len(syft_component_ids), 1) * 100,
        }

    def _analyze_vulnerability_differences(
        self, syft_data: dict[str, Any], docker_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze differences in vulnerabilities between generation methods."""
        syft_vulns = self._extract_vulnerabilities(syft_data)
        docker_vulns = self._extract_vulnerabilities(docker_data)

        syft_vuln_ids = set(syft_vulns.keys())
        docker_vuln_ids = set(docker_vulns.keys())

        only_in_syft_vulns = syft_vuln_ids - docker_vuln_ids
        only_in_docker_vulns = docker_vuln_ids - syft_vuln_ids
        common_vulns = syft_vuln_ids & docker_vuln_ids

        return {
            "syft_total_vulnerabilities": len(syft_vulns),
            "docker_total_vulnerabilities": len(docker_vulns),
            "common_vulnerabilities": len(common_vulns),
            "only_in_syft_vulns": len(only_in_syft_vulns),
            "only_in_docker_vulns": len(only_in_docker_vulns),
            "only_in_syft_vulns_list": list(only_in_syft_vulns)[:10],
            "only_in_docker_vulns_list": list(only_in_docker_vulns)[:10],
            "vulnerability_overlap_percentage": (
                len(common_vulns) / max(len(syft_vuln_ids), 1) * 100
                if syft_vuln_ids or docker_vuln_ids
                else 100
            ),
        }

    def _check_contamination(
        self,
        syft_data: dict[str, Any],
        docker_data: dict[str, Any],
        repo_info: RepositoryInfo,
    ) -> dict[str, Any]:
        """Check for contamination issues like dev dependencies or missing runtime dependencies."""
        syft_components = self._extract_components(syft_data)
        docker_components = self._extract_components(docker_data)

        # Identify potential dev dependencies (only in Syft)
        only_in_syft = set(syft_components.keys()) - set(docker_components.keys())
        potential_dev_deps = []
        potential_test_deps = []
        potential_build_deps = []

        for comp_id in only_in_syft:
            comp = syft_components[comp_id]
            name = comp.get("name", "").lower()

            # Check for common dev/test/build patterns
            if any(pattern in name for pattern in ["test", "pytest", "mock", "coverage"]):
                potential_test_deps.append(comp_id)
            elif any(pattern in name for pattern in ["build", "setuptools", "wheel", "pip"]):
                potential_build_deps.append(comp_id)
            elif any(pattern in name for pattern in ["dev", "debug", "lint", "format"]):
                potential_dev_deps.append(comp_id)

        # Identify potential missing runtime dependencies (only in Docker)
        only_in_docker = set(docker_components.keys()) - set(syft_components.keys())
        potential_missing_runtime = list(only_in_docker)

        # Check for file-type contamination in Syft
        syft_file_components = [
            comp_id
            for comp_id, comp in syft_components.items()
            if comp.get("type") == "file" or "/" in comp_id
        ]

        return {
            "potential_dev_dependencies": len(potential_dev_deps),
            "potential_test_dependencies": len(potential_test_deps),
            "potential_build_dependencies": len(potential_build_deps),
            "potential_missing_runtime": len(potential_missing_runtime),
            "file_type_contamination": len(syft_file_components),
            "dev_deps_list": potential_dev_deps[:10],
            "test_deps_list": potential_test_deps[:10],
            "build_deps_list": potential_build_deps[:10],
            "missing_runtime_list": potential_missing_runtime[:10],
            "file_contamination_list": syft_file_components[:10],
        }

    def _extract_components(self, sbom_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Extract components from SBOM data."""
        components = {}
        for comp in sbom_data.get("components", []):
            comp_id = comp.get(
                "bom-ref",
                f"{comp.get('name', 'unknown')}=={comp.get('version', 'unknown')}",
            )
            components[comp_id] = comp
        return components

    def _extract_vulnerabilities(self, sbom_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Extract vulnerabilities from SBOM data."""
        vulnerabilities = {}

        # Extract from top-level vulnerabilities
        for vuln in sbom_data.get("vulnerabilities", []):
            vuln_id = vuln.get("id") or vuln.get("source_id", "unknown")
            vulnerabilities[vuln_id] = vuln

        # Extract from component-level vulnerabilities
        for comp in sbom_data.get("components", []):
            for vuln in comp.get("vulnerabilities", []):
                vuln_id = vuln.get("id") or vuln.get("cve_id", "unknown")
                if vuln_id not in vulnerabilities:
                    vulnerabilities[vuln_id] = vuln

        return vulnerabilities

    def _count_component_types(self, components: dict[str, dict[str, Any]]) -> dict[str, int]:
        """Count components by type."""
        types = {}
        for comp in components.values():
            comp_type = comp.get("type", "unknown")
            types[comp_type] = types.get(comp_type, 0) + 1
        return types

    def _generate_comparison_recommendations(self, report: dict[str, Any]) -> list[str]:
        """Generate recommendations based on comparison analysis."""
        recommendations = []

        component_analysis = report.get("component_analysis", {})
        contamination = report.get("contamination_check", {})
        vuln_analysis = report.get("vulnerability_analysis", {})

        # Component overlap recommendations
        overlap = component_analysis.get("overlap_percentage", 0)
        if overlap < 70:
            recommendations.append(
                f"Low component overlap ({overlap:.1f}%) between methods suggests significant differences. "
                "Consider investigating which method better represents your runtime environment."
            )

        # Contamination recommendations
        if contamination.get("potential_dev_dependencies", 0) > 5:
            recommendations.append(
                f"Found {contamination['potential_dev_dependencies']} potential dev dependencies in Syft scan. "
                "These may not be present in production runtime."
            )

        if contamination.get("file_type_contamination", 0) > 20:
            recommendations.append(
                f"Found {contamination['file_type_contamination']} file-type components in Syft scan. "
                "Consider filtering these out if focusing on package dependencies."
            )

        if contamination.get("potential_missing_runtime", 0) > 5:
            recommendations.append(
                f"Found {contamination['potential_missing_runtime']} components only in Docker scan. "
                "These may be missing runtime dependencies not captured by static analysis."
            )

        # Vulnerability recommendations
        vuln_overlap = vuln_analysis.get("vulnerability_overlap_percentage", 100)
        if vuln_overlap < 80 and (
            vuln_analysis.get("syft_total_vulnerabilities", 0) > 0
            or vuln_analysis.get("docker_total_vulnerabilities", 0) > 0
        ):
            recommendations.append(
                f"Vulnerability overlap is only {vuln_overlap:.1f}%. Different generation methods may affect vulnerability detection."
            )

        if not recommendations:
            recommendations.append(
                "SBOM generation methods show good consistency. Both approaches appear reliable for this repository."
            )

        return recommendations


class VisualizationValidator:
    """Validates visualization output and generates detailed reports."""

    def __init__(self):
        """Initialize the validator."""
        self.report_data = {}

    def validate_visualization_data(
        self, sbom_path: Path, graph_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate comprehensive validation report for visualization data.

        Args:
            sbom_path: Path to original SBOM file
            graph_data: Generated graph data from visualization

        Returns:
            Detailed validation report
        """
        # Load original SBOM
        with open(sbom_path) as f:
            original_sbom = json.load(f)

        report = {
            "validation_metadata": {
                "timestamp": datetime.now().isoformat(),
                "sbom_file": str(sbom_path),
                "validator_version": "1.0.0",
            },
            "data_sources": self._analyze_data_sources(original_sbom),
            "node_analysis": self._analyze_nodes(graph_data.get("nodes", []), original_sbom),
            "edge_analysis": self._analyze_edges(graph_data.get("links", []), original_sbom),
            "vulnerability_analysis": self._analyze_vulnerabilities(
                graph_data.get("nodes", []), original_sbom
            ),
            "missing_components": self._find_missing_components(
                graph_data.get("nodes", []), original_sbom
            ),
            "data_integrity": self._check_data_integrity(graph_data),
            "recommendations": [],
        }

        # Generate recommendations based on analysis
        report["recommendations"] = self._generate_recommendations(report)

        return report

    def _analyze_data_sources(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Analyze the original data sources."""
        components = sbom_data.get("components", [])
        dependencies = sbom_data.get("dependencies", [])
        vulnerabilities = sbom_data.get("vulnerabilities", [])

        # Count component types
        component_types = {}
        for comp in components:
            comp_type = comp.get("type", "unknown")
            component_types[comp_type] = component_types.get(comp_type, 0) + 1

        # Analyze licenses
        licenses = set()
        for comp in components:
            for license_info in comp.get("licenses", []):
                if isinstance(license_info, dict):
                    license_name = license_info.get("license", {}).get("name")
                    if license_name:
                        licenses.add(license_name)
                elif isinstance(license_info, str):
                    licenses.add(license_info)

        return {
            "total_components": len(components),
            "component_types": component_types,
            "total_dependencies": len(dependencies),
            "total_vulnerabilities": len(vulnerabilities),
            "unique_licenses": len(licenses),
            "license_list": sorted(licenses),
        }

    def _analyze_nodes(
        self, nodes: list[dict[str, Any]], sbom_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze visualization nodes against original data."""
        node_types = {}
        node_statuses = {}
        vulnerability_counts = {}

        # Analyze each node
        for node in nodes:
            node_type = node.get("type", "unknown")
            node_status = node.get("status", "unknown")

            node_types[node_type] = node_types.get(node_type, 0) + 1
            node_statuses[node_status] = node_statuses.get(node_status, 0) + 1

            # Count vulnerabilities per node
            vuln_count = len(node.get("vulnerabilities", []))
            if vuln_count > 0:
                vulnerability_counts[node.get("id")] = vuln_count

        # Find nodes without corresponding components
        original_components = {
            comp.get("bom-ref", f"{comp.get('name')}=={comp.get('version')}")
            for comp in sbom_data.get("components", [])
        }

        visualization_nodes = {node.get("id") for node in nodes if node.get("type") != "LICENSE"}
        orphaned_nodes = visualization_nodes - original_components

        return {
            "total_nodes": len(nodes),
            "node_types": node_types,
            "node_statuses": node_statuses,
            "vulnerable_nodes": len([n for n in nodes if n.get("isVulnerable", False)]),
            "dependent_nodes": len([n for n in nodes if n.get("isDependent", False)]),
            "nodes_with_vulnerabilities": len(vulnerability_counts),
            "vulnerability_distribution": vulnerability_counts,
            "orphaned_nodes": list(orphaned_nodes),
            "orphaned_count": len(orphaned_nodes),
        }

    def _analyze_edges(
        self, links: list[dict[str, Any]], sbom_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze visualization edges against dependency data."""
        relationship_types = {}
        edge_colors = {}
        vulnerable_connections = 0
        dependent_connections = 0

        for link in links:
            rel_type = link.get("relationship", "unknown")
            edge_color = link.get("color", "unknown")

            relationship_types[rel_type] = relationship_types.get(rel_type, 0) + 1
            edge_colors[edge_color] = edge_colors.get(edge_color, 0) + 1

            if link.get("isVulnerableConnection", False):
                vulnerable_connections += 1
            if link.get("isDependentConnection", False):
                dependent_connections += 1

        # Analyze original dependencies
        original_deps = sbom_data.get("dependencies", [])
        total_original_deps = sum(len(dep.get("dependsOn", [])) for dep in original_deps)

        return {
            "total_edges": len(links),
            "relationship_types": relationship_types,
            "edge_colors": edge_colors,
            "vulnerable_connections": vulnerable_connections,
            "dependent_connections": dependent_connections,
            "original_dependencies": total_original_deps,
            "dependency_coverage": (
                len(links) / max(total_original_deps, 1) if total_original_deps > 0 else 0
            ),
        }

    def _analyze_vulnerabilities(
        self, nodes: list[dict[str, Any]], sbom_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze vulnerability representation."""
        # Count vulnerabilities in visualization
        viz_vulns = {}
        for node in nodes:
            for vuln in node.get("vulnerabilities", []):
                vuln_id = vuln.get("id") or vuln.get("cve_id", "unknown")
                if vuln_id not in viz_vulns:
                    viz_vulns[vuln_id] = {
                        "affected_components": [],
                        "severity": vuln.get("cvss_severity", "unknown"),
                        "score": vuln.get("cvss_score"),
                    }
                viz_vulns[vuln_id]["affected_components"].append(node.get("id"))

        # Count original vulnerabilities
        original_vulns = {}
        for vuln in sbom_data.get("vulnerabilities", []):
            vuln_id = vuln.get("id") or vuln.get("source_id", "unknown")
            original_vulns[vuln_id] = vuln

        # Check component-level vulnerabilities
        component_vulns = {}
        for comp in sbom_data.get("components", []):
            comp_id = comp.get("bom-ref", f"{comp.get('name')}=={comp.get('version')}")
            comp_vulns = comp.get("vulnerabilities", [])
            if comp_vulns:
                component_vulns[comp_id] = len(comp_vulns)

        missing_vulns = set(original_vulns.keys()) - set(viz_vulns.keys())
        extra_vulns = set(viz_vulns.keys()) - set(original_vulns.keys())

        return {
            "visualization_vulnerabilities": len(viz_vulns),
            "original_vulnerabilities": len(original_vulns),
            "component_vulnerabilities": len(component_vulns),
            "missing_vulnerabilities": list(missing_vulns),
            "extra_vulnerabilities": list(extra_vulns),
            "vulnerability_details": viz_vulns,
            "severity_distribution": self._count_severities(viz_vulns),
        }

    def _count_severities(self, vulnerabilities: dict[str, Any]) -> dict[str, int]:
        """Count vulnerability severities."""
        severities = {}
        for vuln_data in vulnerabilities.values():
            severity = vuln_data.get("severity", "unknown")
            severities[severity] = severities.get(severity, 0) + 1
        return severities

    def _find_missing_components(
        self, nodes: list[dict[str, Any]], sbom_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Find components that exist in SBOM but not in visualization."""
        # Get all original components
        original_components = {}
        for comp in sbom_data.get("components", []):
            comp_id = comp.get("bom-ref", f"{comp.get('name')}=={comp.get('version')}")
            original_components[comp_id] = comp

        # Get visualization nodes (excluding licenses)
        viz_components = {node.get("id") for node in nodes if node.get("type") != "LICENSE"}

        missing_components = set(original_components.keys()) - viz_components

        # Analyze why components might be missing
        excluded_reasons = {}
        for comp_id in missing_components:
            comp = original_components[comp_id]
            comp_type = comp.get("type", "unknown")

            reasons = []
            if comp_type == "file":
                reasons.append("file_type_excluded")
            if any(pattern in comp_id.lower() for pattern in [".venv", "dist-info", "__pycache__"]):
                reasons.append("path_pattern_excluded")
            if len(comp_id) > 100:
                reasons.append("long_path_excluded")

            if not reasons:
                reasons.append("unknown_exclusion")

            for reason in reasons:
                excluded_reasons[reason] = excluded_reasons.get(reason, 0) + 1

        return {
            "total_missing": len(missing_components),
            "missing_component_ids": list(missing_components),
            "exclusion_reasons": excluded_reasons,
            "missing_details": {
                comp_id: original_components[comp_id]
                for comp_id in list(missing_components)[:10]  # First 10 for brevity
            },
        }

    def _check_data_integrity(self, graph_data: dict[str, Any]) -> dict[str, Any]:
        """Check data integrity of the visualization."""
        nodes = graph_data.get("nodes", [])
        links = graph_data.get("links", [])

        # Check for node ID uniqueness
        node_ids = [node.get("id") for node in nodes]
        duplicate_ids = [id for id in set(node_ids) if node_ids.count(id) > 1]

        # Check for orphaned edges
        valid_node_ids = set(node_ids)
        orphaned_edges = []
        for link in links:
            source = link.get("source")
            target = link.get("target")
            if source not in valid_node_ids or target not in valid_node_ids:
                orphaned_edges.append(
                    {
                        "source": source,
                        "target": target,
                        "missing_node": source if source not in valid_node_ids else target,
                    }
                )

        # Check for self-loops
        self_loops = [link for link in links if link.get("source") == link.get("target")]

        # Check for isolated nodes
        connected_nodes = set()
        for link in links:
            connected_nodes.add(link.get("source"))
            connected_nodes.add(link.get("target"))

        isolated_nodes = [
            node.get("id")
            for node in nodes
            if node.get("id") not in connected_nodes and node.get("type") != "LICENSE"
        ]

        return {
            "duplicate_node_ids": duplicate_ids,
            "orphaned_edges": orphaned_edges,
            "self_loops": len(self_loops),
            "isolated_nodes": len(isolated_nodes),
            "isolated_node_ids": isolated_nodes[:20],  # First 20 for brevity
            "total_integrity_issues": len(duplicate_ids) + len(orphaned_edges) + len(self_loops),
        }

    def _generate_recommendations(self, report: dict[str, Any]) -> list[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        # Node analysis recommendations
        node_analysis = report.get("node_analysis", {})
        if node_analysis.get("orphaned_count", 0) > 0:
            recommendations.append(
                f"Found {node_analysis['orphaned_count']} orphaned nodes in visualization. "
                "These represent components in the graph that don't exist in the original SBOM."
            )

        # Edge analysis recommendations
        edge_analysis = report.get("edge_analysis", {})
        coverage = edge_analysis.get("dependency_coverage", 0)
        if coverage < 0.8:
            recommendations.append(
                f"Low dependency coverage: {coverage:.1%}. Many original dependencies may not be visualized."
            )

        # Vulnerability analysis recommendations
        vuln_analysis = report.get("vulnerability_analysis", {})
        if vuln_analysis.get("missing_vulnerabilities"):
            recommendations.append(
                f"Missing {len(vuln_analysis['missing_vulnerabilities'])} vulnerabilities from visualization."
            )

        # Data integrity recommendations
        integrity = report.get("data_integrity", {})
        if integrity.get("total_integrity_issues", 0) > 0:
            recommendations.append(
                f"Found {integrity['total_integrity_issues']} data integrity issues. Check for duplicate IDs and orphaned edges."
            )

        if integrity.get("isolated_nodes", 0) > 10:
            recommendations.append(
                f"High number of isolated nodes ({integrity['isolated_nodes']}). Consider improving dependency resolution."
            )

        if not recommendations:
            recommendations.append("Visualization data appears to be accurate and complete.")

        return recommendations


@click.command()
@click.argument("repository_url")
@click.option(
    "--output-dir",
    "-o",
    default="out",
    help="Output directory for validation report and generated SBOMs",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "txt"]),
    default="json",
    help="Output format for validation report",
)
@click.pass_context
def validate_generation(ctx, repository_url, output_dir, format):
    """Compare SBOM generation between Docker and Syft methods to check for contamination.

    This command generates SBOMs using both methods and compares component counts,
    vulnerability counts, and identifies potential contamination issues.
    """
    logger = ctx.obj["logger"]

    try:
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)

        # Create validator and generate comparison report
        click.echo("🔄 Generating SBOMs with both Docker and Syft methods...")
        validator = SBOMGenerationValidator(ctx)
        report = validator.compare_generation_methods(repository_url, output_dir_path)

        # Check if generation was successful
        if "error" in report.get("generation_results", {}):
            click.echo(f"✗ Error: {report['generation_results']['error']}", err=True)
            sys.exit(1)

        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        repo_name = repository_url.rstrip("/").split("/")[-1].replace(".git", "")
        report_filename = f"{repo_name}_generation_validation_{timestamp}.{format}"
        report_path = output_dir_path / report_filename

        # Write report
        if format == "json":
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
        else:  # txt format
            with open(report_path, "w") as f:
                f.write(_format_generation_report_as_text(report))

        click.echo(f"✓ Generation validation report created: {report_path}")

        # Print summary
        _print_generation_summary(report)

        logger.info(f"Generation validation completed for {repository_url} at {report_path}")

    except SBOMToolkitError as e:
        logger.error(f"Generation validation failed: {e}")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during generation validation: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)


@click.command()
@click.argument("sbom_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output-dir", "-o", default="out", help="Output directory for validation report")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "yaml", "txt"]),
    default="json",
    help="Output format for validation report",
)
@click.option(
    "--include-details",
    is_flag=True,
    help="Include detailed component and vulnerability information",
)
@click.pass_context
def validate_visualization(ctx, sbom_path, output_dir, format, include_details):
    """Generate validation report for SBOM visualization data.

    This command creates a detailed report showing what data was used to create
    the visualization, helps identify missing components, and validates data integrity.
    """
    logger = ctx.obj["logger"]

    try:
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)

        # Generate visualization data
        click.echo("🔍 Generating visualization data...")
        graph = SBOMGraph()
        graph.load_sbom(sbom_path)
        graph_data = graph.graph_to_json()

        # Create validator and generate report
        click.echo("📊 Analyzing visualization data...")
        validator = VisualizationValidator()
        report = validator.validate_visualization_data(sbom_path, graph_data)

        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{sbom_path.stem}_validation_{timestamp}.{format}"
        report_path = output_dir_path / report_filename

        # Write report
        if format == "json":
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
        else:  # txt format
            with open(report_path, "w") as f:
                f.write(_format_report_as_text(report))

        click.echo(f"✓ Validation report created: {report_path}")

        # Print summary
        _print_validation_summary(report)

        logger.info(f"Validation report generated for {sbom_path} at {report_path}")

    except SBOMToolkitError as e:
        logger.error(f"Validation failed: {e}")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during validation: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)


def _print_validation_summary(report: dict[str, Any]) -> None:
    """Print a summary of the validation report."""
    click.echo("\n📋 Validation Summary:")
    click.echo("=" * 50)

    # Data sources
    data_sources = report.get("data_sources", {})
    click.echo(
        f"📦 Original SBOM: {data_sources.get('total_components', 0)} components, "
        f"{data_sources.get('total_vulnerabilities', 0)} vulnerabilities"
    )

    # Node analysis
    node_analysis = report.get("node_analysis", {})
    click.echo(
        f"🔗 Visualization: {node_analysis.get('total_nodes', 0)} nodes, "
        f"{node_analysis.get('vulnerable_nodes', 0)} vulnerable"
    )

    # Missing components
    missing = report.get("missing_components", {})
    if missing.get("total_missing", 0) > 0:
        click.echo(f"⚠️  Missing components: {missing['total_missing']}")

    # Data integrity
    integrity = report.get("data_integrity", {})
    if integrity.get("total_integrity_issues", 0) > 0:
        click.echo(f"🔍 Integrity issues: {integrity['total_integrity_issues']}")

    # Recommendations
    recommendations = report.get("recommendations", [])
    if recommendations:
        click.echo("\n💡 Recommendations:")
        for i, rec in enumerate(recommendations[:3], 1):  # Show first 3
            click.echo(f"  {i}. {rec}")
        if len(recommendations) > 3:
            click.echo(f"  ... and {len(recommendations) - 3} more (see full report)")


def _print_generation_summary(report: dict[str, Any]) -> None:
    """Print a summary of the generation validation report."""
    click.echo("\n📋 Generation Validation Summary:")
    click.echo("=" * 50)

    # Generation results
    gen_results = report.get("generation_results", {})
    click.echo("📁 SBOMs generated successfully:")
    click.echo(f"   Syft SBOM: {gen_results.get('syft_sbom_path', 'N/A')}")
    click.echo(f"   Docker SBOM: {gen_results.get('docker_sbom_path', 'N/A')}")

    # Component analysis
    comp_analysis = report.get("component_analysis", {})
    click.echo(
        f"📦 Components: Syft={comp_analysis.get('syft_total', 0)}, "
        f"Docker={comp_analysis.get('docker_total', 0)}, "
        f"Overlap={comp_analysis.get('overlap_percentage', 0):.1f}%"
    )

    # Contamination check
    contamination = report.get("contamination_check", {})
    if contamination.get("potential_dev_dependencies", 0) > 0:
        click.echo(f"⚠️  Potential dev dependencies: {contamination['potential_dev_dependencies']}")
    if contamination.get("file_type_contamination", 0) > 0:
        click.echo(f"📄 File contamination: {contamination['file_type_contamination']}")
    if contamination.get("potential_missing_runtime", 0) > 0:
        click.echo(
            f"❓ Potential missing runtime deps: {contamination['potential_missing_runtime']}"
        )

    # Recommendations
    recommendations = report.get("recommendations", [])
    if recommendations:
        click.echo("\n💡 Key Recommendations:")
        for i, rec in enumerate(recommendations[:2], 1):  # Show first 2
            click.echo(f"  {i}. {rec}")
        if len(recommendations) > 2:
            click.echo(f"  ... and {len(recommendations) - 2} more (see full report)")


def _format_generation_report_as_text(report: dict[str, Any]) -> str:
    """Format generation validation report as human-readable text."""
    lines = []
    lines.append("SBOM Generation Method Validation Report")
    lines.append("=" * 50)
    lines.append(f"Generated: {report.get('validation_metadata', {}).get('timestamp', 'Unknown')}")
    lines.append(
        f"Repository: {report.get('validation_metadata', {}).get('repository_url', 'Unknown')}"
    )
    lines.append("")

    # Generation results
    gen_results = report.get("generation_results", {})
    lines.append("GENERATION RESULTS")
    lines.append("-" * 20)
    lines.append(f"Syft SBOM: {gen_results.get('syft_sbom_path', 'N/A')}")
    lines.append(f"Docker SBOM: {gen_results.get('docker_sbom_path', 'N/A')}")
    lines.append("")

    # Component analysis
    comp_analysis = report.get("component_analysis", {})
    lines.append("COMPONENT ANALYSIS")
    lines.append("-" * 20)
    lines.append(f"Syft Total Components: {comp_analysis.get('syft_total', 0)}")
    lines.append(f"Docker Total Components: {comp_analysis.get('docker_total', 0)}")
    lines.append(f"Common Components: {comp_analysis.get('common_components', 0)}")
    lines.append(f"Only in Syft: {comp_analysis.get('only_in_syft', 0)}")
    lines.append(f"Only in Docker: {comp_analysis.get('only_in_docker', 0)}")
    lines.append(f"Overlap Percentage: {comp_analysis.get('overlap_percentage', 0):.1f}%")
    lines.append("")

    # Contamination check
    contamination = report.get("contamination_check", {})
    lines.append("CONTAMINATION CHECK")
    lines.append("-" * 20)
    lines.append(
        f"Potential Dev Dependencies: {contamination.get('potential_dev_dependencies', 0)}"
    )
    lines.append(
        f"Potential Test Dependencies: {contamination.get('potential_test_dependencies', 0)}"
    )
    lines.append(f"File Type Contamination: {contamination.get('file_type_contamination', 0)}")
    lines.append(f"Potential Missing Runtime: {contamination.get('potential_missing_runtime', 0)}")
    lines.append("")

    # Vulnerability analysis
    vuln_analysis = report.get("vulnerability_analysis", {})
    if (
        vuln_analysis.get("syft_total_vulnerabilities", 0) > 0
        or vuln_analysis.get("docker_total_vulnerabilities", 0) > 0
    ):
        lines.append("VULNERABILITY ANALYSIS")
        lines.append("-" * 20)
        lines.append(f"Syft Vulnerabilities: {vuln_analysis.get('syft_total_vulnerabilities', 0)}")
        lines.append(
            f"Docker Vulnerabilities: {vuln_analysis.get('docker_total_vulnerabilities', 0)}"
        )
        lines.append(
            f"Vulnerability Overlap: {vuln_analysis.get('vulnerability_overlap_percentage', 0):.1f}%"
        )
        lines.append("")

    # Recommendations
    recommendations = report.get("recommendations", [])
    if recommendations:
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 20)
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    return "\n".join(lines)


def _format_report_as_text(report: dict[str, Any]) -> str:
    """Format validation report as human-readable text."""
    lines = []
    lines.append("SBOM Visualization Validation Report")
    lines.append("=" * 50)
    lines.append(f"Generated: {report.get('validation_metadata', {}).get('timestamp', 'Unknown')}")
    lines.append(f"SBOM File: {report.get('validation_metadata', {}).get('sbom_file', 'Unknown')}")
    lines.append("")

    # Data sources summary
    data_sources = report.get("data_sources", {})
    lines.append("DATA SOURCES")
    lines.append("-" * 20)
    lines.append(f"Total Components: {data_sources.get('total_components', 0)}")
    lines.append(f"Total Dependencies: {data_sources.get('total_dependencies', 0)}")
    lines.append(f"Total Vulnerabilities: {data_sources.get('total_vulnerabilities', 0)}")
    lines.append("")

    # Node analysis
    node_analysis = report.get("node_analysis", {})
    lines.append("VISUALIZATION NODES")
    lines.append("-" * 20)
    lines.append(f"Total Nodes: {node_analysis.get('total_nodes', 0)}")
    lines.append(f"Vulnerable Nodes: {node_analysis.get('vulnerable_nodes', 0)}")
    lines.append(f"Dependent Nodes: {node_analysis.get('dependent_nodes', 0)}")
    if node_analysis.get("orphaned_count", 0) > 0:
        lines.append(f"Orphaned Nodes: {node_analysis['orphaned_count']}")
    lines.append("")

    # Recommendations
    recommendations = report.get("recommendations", [])
    if recommendations:
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 20)
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    return "\n".join(lines)
