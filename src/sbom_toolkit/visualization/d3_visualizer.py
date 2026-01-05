"""
D3.js-based SBOM visualization system.

This module generates interactive SBOM visualizations using D3.js with full control
panel integration. It consumes JSON output from the graph generators and creates
standalone HTML files with embedded data and functionality.
"""

import json
import logging
from pathlib import Path
from typing import Any

from ..shared.exceptions import SBOMError, create_error_context


class D3Visualizer:
    """Interactive SBOM visualization using D3.js."""

    def __init__(self):
        """Initialize D3 visualizer."""
        self.logger = logging.getLogger(__name__)

    def create_force_directed_visualization(
        self,
        graph_data: dict[str, Any],
        sbom_metadata: dict[str, Any],
        output_path: Path,
        gnn_predictions: dict[str, Any] | None = None,
    ) -> Path:
        """Create force-directed network visualization.

        Args:
            graph_data: JSON output from SBOMGraph.graph_to_json()
            sbom_metadata: SBOM metadata for context
            output_path: Output HTML file path
            gnn_predictions: Optional GNN predictions data

        Returns:
            Path to generated HTML file
        """
        template_data = {
            "title": "SBOM Force-Directed Network",
            "layout_type": "force_directed",
            "graph_data": graph_data,
            "sbom_metadata": sbom_metadata,
            "gnn_predictions": gnn_predictions or {},
            "statistics": self._calculate_statistics(graph_data),
        }

        return self._generate_html(template_data, output_path, "force_directed")

    def create_hierarchical_visualization(
        self,
        hierarchy_data: dict[str, Any],
        sbom_metadata: dict[str, Any],
        output_path: Path,
        gnn_predictions: dict[str, Any] | None = None,
    ) -> Path:
        """Create hierarchical tree visualization.

        Args:
            hierarchy_data: JSON output from HierarchicalSBOMGraph.graph_to_json()
            sbom_metadata: SBOM metadata for context
            output_path: Output HTML file path
            gnn_predictions: Optional GNN predictions data

        Returns:
            Path to generated HTML file
        """
        template_data = {
            "title": "SBOM Dependency Tree",
            "layout_type": "hierarchical",
            "hierarchy_data": hierarchy_data,
            "sbom_metadata": sbom_metadata,
            "gnn_predictions": gnn_predictions or {},
            "statistics": self._calculate_hierarchical_statistics(hierarchy_data),
        }

        return self._generate_html(template_data, output_path, "hierarchical")

    def create_circular_visualization(
        self,
        graph_data: dict[str, Any],
        sbom_metadata: dict[str, Any],
        output_path: Path,
        gnn_predictions: dict[str, Any] | None = None,
    ) -> Path:
        """Create circular/radial layout visualization.

        Args:
            graph_data: JSON output from SBOMGraph.graph_to_json()
            sbom_metadata: SBOM metadata for context
            output_path: Output HTML file path
            gnn_predictions: Optional GNN predictions data

        Returns:
            Path to generated HTML file
        """
        template_data = {
            "title": "SBOM Circular Network",
            "layout_type": "circular",
            "graph_data": graph_data,
            "sbom_metadata": sbom_metadata,
            "gnn_predictions": gnn_predictions or {},
            "statistics": self._calculate_statistics(graph_data),
        }

        return self._generate_html(template_data, output_path, "circular")

    def _calculate_statistics(self, graph_data: dict[str, Any]) -> dict[str, int]:
        """Calculate network statistics from graph data.

        Args:
            graph_data: Graph data with nodes and links

        Returns:
            Dictionary with statistics
        """
        nodes = graph_data.get("nodes", [])

        total_components = sum(1 for node in nodes if node.get("type") == "LIBRARY")
        total_licenses = sum(1 for node in nodes if node.get("type") == "LICENSE")
        vulnerable_count = sum(1 for node in nodes if node.get("isVulnerable", False))
        safe_count = total_components - vulnerable_count

        return {
            "total_components": total_components,
            "total_licenses": total_licenses,
            "vulnerable_count": vulnerable_count,
            "safe_count": safe_count,
            "total_links": len(graph_data.get("links", [])),
        }

    def _calculate_hierarchical_statistics(self, hierarchy_data: dict[str, Any]) -> dict[str, int]:
        """Calculate statistics from hierarchical data.

        Args:
            hierarchy_data: Hierarchical tree data

        Returns:
            Dictionary with statistics
        """

        def count_nodes(node):
            counts = {
                "components": 1 if node.get("type") == "LIBRARY" else 0,
                "licenses": len(node.get("licenses", [])),
                "vulnerable": 1 if node.get("isVulnerable", False) else 0,
            }

            for child in node.get("children", []):
                child_counts = count_nodes(child)
                counts["components"] += child_counts["components"]
                counts["licenses"] += child_counts["licenses"]
                counts["vulnerable"] += child_counts["vulnerable"]

            return counts

        counts = count_nodes(hierarchy_data)
        return {
            "total_components": counts["components"],
            "total_licenses": counts["licenses"],
            "vulnerable_count": counts["vulnerable"],
            "safe_count": counts["components"] - counts["vulnerable"],
            "total_links": 0,  # Not applicable for hierarchical
        }

    def _generate_html(
        self, template_data: dict[str, Any], output_path: Path, layout_type: str
    ) -> Path:
        """Generate HTML file with embedded D3.js visualization.

        Args:
            template_data: Data to embed in template
            output_path: Output file path
            layout_type: Type of layout (force_directed, hierarchical, circular)

        Returns:
            Path to generated HTML file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Load the appropriate D3.js template
        template_path = Path(__file__).parent / "templates" / f"d3_{layout_type}_template.html"

        if not template_path.exists():
            raise SBOMError(
                f"Template not found: {template_path}",
                create_error_context(operation="generate_html"),
            )

        with open(template_path, encoding="utf-8") as f:
            template_content = f.read()

        # Replace template placeholders with actual data
        html_content = self._populate_template(template_content, template_data)

        # Write the final HTML
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        self.logger.info("D3.js visualization saved to: %s", output_path)
        return output_path

    def _populate_template(self, template: str, data: dict[str, Any]) -> str:
        """Populate template with data.

        Args:
            template: HTML template string
            data: Data to embed

        Returns:
            Populated HTML string
        """
        # Your existing templates use different placeholders, so we need to align them
        graph_data = data.get("graph_data") or data.get("hierarchy_data")

        # Safely serialize graph data to JSON
        graph_data_json = json.dumps(graph_data, indent=2, default=str)

        # Replace template placeholders - handle both Jinja2 and simple syntax
        result = template

        # Handle Jinja2-style placeholders first
        result = result.replace("{{GRAPH_DATA|tojson|safe}}", graph_data_json)
        # Handle simple placeholders as fallback
        result = result.replace("{{GRAPH_DATA}}", graph_data_json)

        # Handle any other placeholders your templates might have
        additional_replacements = {
            "{{TITLE}}": data["title"],
            "{{LAYOUT_TYPE}}": data["layout_type"],
            "{{TOTAL_COMPONENTS}}": str(data["statistics"]["total_components"]),
            "{{TOTAL_LICENSES}}": str(data["statistics"]["total_licenses"]),
            "{{VULNERABLE_COUNT}}": str(data["statistics"]["vulnerable_count"]),
            "{{SAFE_COUNT}}": str(data["statistics"]["safe_count"]),
        }

        for placeholder, value in additional_replacements.items():
            result = result.replace(placeholder, value)

        return result


def create_d3_visualization(
    sbom_path: Path,
    output_path: Path,
    layout_type: str = "force_directed",
    gnn_predictions: dict[str, Any] | None = None,
) -> Path:
    """Create D3.js SBOM visualization.

    Args:
        sbom_path: Path to SBOM JSON file
        output_path: Output path for HTML file
        layout_type: Layout type (force_directed, hierarchical, circular)
        gnn_predictions: Optional GNN predictions

    Returns:
        Path to generated HTML file
    """
    from .legacy.f_graph_generator import SBOMGraph
    from .legacy.h_graph_generator import HierarchicalSBOMGraph

    # Load SBOM data
    with open(sbom_path) as f:
        sbom_data = json.load(f)

    sbom_metadata = sbom_data.get("metadata", {})

    visualizer = D3Visualizer()

    if layout_type == "hierarchical":
        # Use hierarchical graph generator
        graph = HierarchicalSBOMGraph()
        graph.load_sbom(sbom_path)
        hierarchy_data = graph.graph_to_json()

        return visualizer.create_hierarchical_visualization(
            hierarchy_data, sbom_metadata, output_path, gnn_predictions
        )
    else:
        # Use force-directed graph generator for both force and circular layouts
        graph = SBOMGraph()
        graph.load_sbom(sbom_path)
        graph_data = graph.graph_to_json()

        if layout_type == "circular":
            return visualizer.create_circular_visualization(
                graph_data, sbom_metadata, output_path, gnn_predictions
            )
        else:  # force_directed
            return visualizer.create_force_directed_visualization(
                graph_data, sbom_metadata, output_path, gnn_predictions
            )
