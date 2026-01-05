"""
Force-directed layout engine for SBOM visualization.

This engine creates network-style visualizations where nodes repel each other
and edges act as springs, creating organic layouts that highlight clustering.
"""

import logging
from typing import Any

import networkx as nx

from ..core.graph_processors import NetworkGraphProcessor


class ForceDirectedEngine:
    """Engine for creating force-directed network visualizations."""

    def __init__(self):
        """Initialize the force-directed engine."""
        self.logger = logging.getLogger(__name__)
        self.graph_processor = NetworkGraphProcessor()

    def process_sbom_data(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Process SBOM data into force-directed visualization format.

        Args:
            sbom_data: Transformed SBOM data

        Returns:
            Dictionary with nodes and links for D3.js force simulation
        """
        # Create NetworkX graph
        graph = self.graph_processor.create_graph_from_sbom(sbom_data)

        # Convert to D3.js format
        visualization_data = self._convert_to_d3_format(graph, sbom_data)

        return visualization_data

    def _convert_to_d3_format(self, graph: nx.Graph, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Convert NetworkX graph to D3.js force-directed format.

        Args:
            graph: NetworkX graph
            sbom_data: Original SBOM data for additional context

        Returns:
            Dictionary with nodes and links arrays
        """
        # Identify vulnerable and dependent nodes
        vulnerable_nodes = set()
        dependent_nodes = set()

        for node, attrs in graph.nodes(data=True):
            if attrs.get("status") == "VULN" and attrs.get("type") != "LICENSE":
                vulnerable_nodes.add(node)
            elif attrs.get("status") == "WEAK" and attrs.get("type") != "LICENSE":
                dependent_nodes.add(node)

        # Build nodes array
        nodes = []
        for node_id, attrs in graph.nodes(data=True):
            if not attrs:
                continue

            is_license = attrs.get("type") == "LICENSE"
            is_vulnerable = attrs.get("status") == "VULN" and not is_license
            is_dependent = attrs.get("status") == "WEAK" and not is_license

            # Get vulnerability information
            vulnerability_info = attrs.get("vulnerabilities", [])
            if not vulnerability_info and is_vulnerable:
                vulnerability_info = self._extract_vulnerability_info(node_id, sbom_data)

            # Build node data
            node_data = {
                "id": str(node_id),
                "fullLabel": attrs.get("full_label", str(node_id)),
                "label": attrs.get("abbreviated_label", str(node_id)),
                "type": attrs.get("type", "LIBRARY"),
                "status": attrs.get("status", "DEFAULT"),
                "color": attrs.get("color", "#808080"),
                "size": attrs.get("size", 40),
                "layer": attrs.get("layer", 0),
                "description": attrs.get("description", ""),
                "isVulnerable": is_vulnerable,
                "isDependent": is_dependent,
                "vulnerabilities": vulnerability_info,
                "isRoot": attrs.get("is_root", False),
            }

            nodes.append(node_data)

        # Build links array
        links = []
        vulnerable_connections = set()
        dependent_connections = set()

        # Find connections involving vulnerable components
        for source, target, _attrs in graph.edges(data=True):
            edge_tuple = tuple(sorted((str(source), str(target))))

            source_is_vuln = source in vulnerable_nodes
            target_is_vuln = target in vulnerable_nodes
            source_is_license = graph.nodes[source].get("type") == "LICENSE"
            target_is_license = graph.nodes[target].get("type") == "LICENSE"

            # Mark vulnerable connections (from vulnerable to non-vulnerable, excluding licenses)
            if (source_is_vuln and not target_is_vuln and not target_is_license) or (
                target_is_vuln and not source_is_vuln and not source_is_license
            ):
                vulnerable_connections.add(edge_tuple)

            # Mark dependent connections
            if (source in dependent_nodes and target in vulnerable_nodes) or (
                target in dependent_nodes and source in vulnerable_nodes
            ):
                dependent_connections.add(edge_tuple)

        # Create links
        for source, target, attrs in graph.edges(data=True):
            edge_tuple = tuple(sorted((str(source), str(target))))

            is_vulnerable_connection = edge_tuple in vulnerable_connections
            is_dependent_connection = edge_tuple in dependent_connections

            # Determine edge color and width
            edge_color = attrs.get("color", "#a8a8a8")
            edge_width = 1

            if is_vulnerable_connection:
                edge_color = "#FF5252"  # Red for vulnerable paths
                edge_width = 3
            elif is_dependent_connection:
                edge_color = "#FFA500"  # Orange for dependent paths
                edge_width = 2

            link_data = {
                "source": str(source),
                "target": str(target),
                "weight": attrs.get("weight", 1),
                "color": edge_color,
                "width": edge_width,
                "relationship": attrs.get("relationship", "unknown"),
                "isVulnerableConnection": is_vulnerable_connection,
                "isDependentConnection": is_dependent_connection,
            }

            links.append(link_data)

        self.logger.info(f"Created force-directed data: {len(nodes)} nodes, {len(links)} links")

        return {
            "nodes": nodes,
            "links": links,
            "statistics": {
                "total_nodes": len(nodes),
                "total_links": len(links),
                "vulnerable_nodes": len(vulnerable_nodes),
                "dependent_nodes": len(dependent_nodes),
            },
        }

    def _extract_vulnerability_info(
        self, node_id: str, sbom_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract vulnerability information for a node from SBOM data.

        Args:
            node_id: Node identifier
            sbom_data: SBOM data

        Returns:
            List of vulnerability information
        """
        vulnerability_info = []

        # Check component vulnerabilities
        for component in sbom_data.get("components", []):
            comp_id = component.get(
                "bom-ref", f"{component.get('name')}=={component.get('version')}"
            )
            if comp_id == node_id:
                for vuln in component.get("vulnerabilities", []):
                    vulnerability_info.append(
                        {
                            "id": vuln.get("id", vuln.get("cve_id", "Unknown")),
                            "cve_id": vuln.get("cve_id", "Unknown"),
                            "description": vuln.get("description", "No description available"),
                            "cvss_score": vuln.get("cvss_score"),
                            "cvss_severity": vuln.get("cvss_severity", "Unknown"),
                            "cvss_vector": vuln.get("cvss_vector", "N/A"),
                            "references": vuln.get("references", []),
                        }
                    )
                break

        # Check top-level vulnerabilities
        for vuln in sbom_data.get("vulnerabilities", []):
            for affect in vuln.get("affects", []):
                if affect.get("ref") == node_id:
                    vulnerability_info.append(
                        {
                            "id": vuln.get("id", vuln.get("cve_id", "Unknown")),
                            "cve_id": vuln.get("cve_id", "Unknown"),
                            "description": vuln.get("description", "No description available"),
                            "cvss_score": vuln.get("cvss_score"),
                            "cvss_severity": vuln.get("cvss_severity", "Unknown"),
                            "cvss_vector": vuln.get("cvss_vector", "N/A"),
                            "references": vuln.get("references", []),
                        }
                    )
                    break

        return vulnerability_info

    def get_layout_config(self) -> dict[str, Any]:
        """Get D3.js force simulation configuration.

        Returns:
            Configuration dictionary for D3.js force simulation
        """
        return {
            "simulation": {
                "charge": -300,
                "linkDistance": 50,
                "linkStrength": 0.7,
                "collisionRadius": 30,
                "centerStrength": 0.1,
                "velocityDecay": 0.4,
            },
            "node_settings": {
                "min_radius": 5,
                "max_radius": 25,
                "stroke_width": 2,
                "opacity": 0.8,
            },
            "link_settings": {"min_width": 1, "max_width": 5, "opacity": 0.6},
        }
