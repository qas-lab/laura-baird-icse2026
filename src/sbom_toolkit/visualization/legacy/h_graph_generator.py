"""
This module provides functionality to generate a hierarchical graph visualization of a Software Bill of Materials (SBOM).
"""

import json
from pathlib import Path
from typing import Any

# Try to import GNN prediction function, fallback if not available
import networkx as nx

# Type alias for prediction result to match the actual function
PredictionResult = dict[str, dict[str, str | float]]

try:
    from src.sbom_toolkit.ml.gnn_predict import predict_sbom

    GNN_AVAILABLE = True
except ImportError:
    try:
        from ...ml.gnn_predict import predict_sbom

        GNN_AVAILABLE = True
    except ImportError:
        # Only print warning when actually trying to use GNN predictions
        def predict_sbom(
            sbom_path: str | Path, model_path: str | Path = "best_model.pt"
        ) -> PredictionResult | None:
            return None

        GNN_AVAILABLE = False


class HierarchicalSBOMGraph:
    """Generate a hierarchical graph visualization of an SBOM.

    This class creates a directed acyclic graph (DAG) representing the
    dependency structure of an SBOM. It prepares the data for rendering
    using a hierarchical layout (e.g., D3 tree or cluster).

    Attributes:
        graph (nx.DiGraph): The NetworkX directed graph object.
        NODE_TYPES (dict): A dictionary defining node types and styles.
        sbom_data (dict): The SBOM data loaded from a JSON file.
    """

    def __init__(self):
        """Initialize the HierarchicalSBOMGraph object."""
        self.graph = nx.DiGraph()
        self.NODE_TYPES: dict[str, Any] = {
            "SBOM": {"color": "#808080", "size": 80},  # Grey
            "LIBRARY": {
                "SAFE": {"color": "#7FD13B", "size": 40},  # Green
                "WEAK": {"color": "#FFA500", "size": 40},  # Orange
                "VULN": {"color": "#FF5252", "size": 40},  # Red
                "DEFAULT": {"color": "#4169E1", "size": 40},  # Blue
            },
            "LICENSE": {"color": "#800080", "size": 25},  # Purple
        }
        self.sbom_data = None

    def _get_abbreviated_label(self, full_label, node_type):
        """Create abbreviated label while preserving important information"""
        if node_type == "SBOM":
            return full_label
        elif node_type == "LICENSE":
            label = full_label.replace("License :: OSI Approved :: ", "")
            return label[:20] + "..." if len(label) > 20 else label
        else:  # LIBRARY
            if "==" in full_label:
                return full_label.split("==")[0]
            return full_label

    def load_sbom(self, sbom_file):
        """Load and parse SBOM data from a JSON file"""
        try:
            with open(sbom_file) as f:
                raw_sbom_data = json.load(f)
        except FileNotFoundError:
            print(f"Error: SBOM file not found at {sbom_file}")
            raise
        except json.JSONDecodeError:
            print(f"Error: Could not decode JSON from {sbom_file}")
            raise

        # Apply data transformation to clean up problematic components
        try:
            from ..core.data_transformer import SBOMDataTransformer

            transformer = SBOMDataTransformer()
            self.sbom_data = transformer.transform_sbom_data(raw_sbom_data)
            print(f"Applied data transformation to SBOM from {sbom_file}")
        except Exception as e:
            print(f"Warning: Could not apply data transformation: {e}")
            self.sbom_data = raw_sbom_data

        metadata = self.sbom_data.get("metadata", {})
        component = metadata.get("component", {})
        if not isinstance(component, dict):
            component = {}

        print(f"DEBUG [load_sbom]: Found metadata.component: {component}")

        root_ref = component.get("bom-ref")
        root_name = component.get("name", "Unnamed Project")
        root_version = component.get("version", "N/A")

        if root_name == "Unnamed Project" or not root_name:
            repo_info = metadata.get("repository", {})
            if isinstance(repo_info, dict) and repo_info.get("name"):
                print(
                    f"DEBUG [load_sbom]: Using repository name '{repo_info['name']}' as fallback for root."
                )
                root_name = repo_info["name"]

        if not root_ref:
            root_ref = f"{root_name}=={root_version}"

        full_label = f"{root_name}=={root_version}"
        abbreviated_label = self._get_abbreviated_label(full_label, "LIBRARY")
        description = component.get("description", "")

        self.graph.add_node(
            root_ref,
            type="LIBRARY",
            status="DEFAULT",
            color=self.NODE_TYPES["LIBRARY"]["DEFAULT"]["color"],
            size=self.NODE_TYPES["LIBRARY"]["DEFAULT"]["size"],
            full_label=full_label,
            abbreviated_label=abbreviated_label,
            description=description,
            is_root=True,
        )

        self._process_components(root_ref)
        self._process_dependencies(root_ref)

        # --- Add GNN Predictions ---
        print("Attempting to add GNN predictions to hierarchical graph...")
        predictions = {}  # Skip GNN predictions for now to debug core functionality
        if GNN_AVAILABLE and False:  # Temporarily disabled
            model_file_path = Path("out/model/best_model.pt")
            predictions = predict_sbom(sbom_path=sbom_file, model_path=model_file_path)
        if predictions is None:
            print("Warning: GNN prediction failed or returned None. Skipping GNN attributes.")
            # Set default values for all library nodes if prediction fails
            for _node_id, node_data in self.graph.nodes(data=True):
                if node_data.get("type") == "LIBRARY":
                    node_data["gnn_prediction"] = "Error"
                    node_data["gnn_confidence"] = 0.0
        else:
            print(f"Received {len(predictions)} GNN predictions.")
            # Apply predictions or defaults
            for node_id, node_data in self.graph.nodes(data=True):
                if node_data.get("type") == "LIBRARY":
                    prediction = predictions.get(node_id)
                    if prediction:
                        node_data["gnn_prediction"] = prediction.get("prediction", "Unknown")
                        node_data["gnn_confidence"] = prediction.get("confidence", 0.0)
                    else:
                        # Set default if node_id not found in predictions
                        node_data["gnn_prediction"] = "Unknown"
                        node_data["gnn_confidence"] = 0.0
        # --- End GNN Predictions ---

    def _get_component_status(self, component):
        """Determine component status based on vulnerabilities"""
        component_ref = component.get("bom-ref")
        if not component_ref:
            lib_name = component.get("name", "Unknown Component")
            lib_version = component.get("version", "unknown")
            component_ref = f"{lib_name}=={lib_version}"

        if "vulnerabilities" in component and component["vulnerabilities"]:
            return "VULN"

        if self.sbom_data and "vulnerabilities" in self.sbom_data:
            top_level_vulns = self.sbom_data["vulnerabilities"]
            for vuln in top_level_vulns:
                if "affects" in vuln:
                    for affect in vuln["affects"]:
                        if affect.get("ref") == component_ref:
                            return "VULN"

        return "DEFAULT"

    def _process_components(self, root_ref):
        """Process components and their licenses"""
        if not self.sbom_data or "components" not in self.sbom_data:
            print("Warning: No 'components' found in SBOM data.")
            return

        for component in self.sbom_data.get("components", []):
            component_ref = component.get("bom-ref")
            if not component_ref:
                lib_name = component.get("name", "Unknown Component")
                lib_version = component.get("version", "unknown")
                component_ref = f"{lib_name}=={lib_version}"

            status = self._get_component_status(component)
            node_style = self.NODE_TYPES["LIBRARY"][status]

            if component_ref == root_ref and self.graph.has_node(root_ref):
                full_label = (
                    f"{component.get('name', 'Unknown')}=={component.get('version', 'latest')}"
                )
                self.graph.nodes[root_ref].update(
                    {
                        "status": status,
                        "color": node_style["color"],
                        "size": node_style["size"],
                        "full_label": full_label,
                        "abbreviated_label": self._get_abbreviated_label(full_label, "LIBRARY"),
                        "description": component.get("description", ""),
                    }
                )
            elif not self.graph.has_node(component_ref):
                full_label = (
                    f"{component.get('name', 'Unknown')}=={component.get('version', 'unknown')}"
                )
                self.graph.add_node(
                    component_ref,
                    type="LIBRARY",
                    status=status,
                    color=node_style["color"],
                    size=node_style["size"],
                    full_label=full_label,
                    abbreviated_label=self._get_abbreviated_label(full_label, "LIBRARY"),
                    description=component.get("description", ""),
                )

            if "licenses" in component:
                standard_licenses = []
                descriptive_licenses = []
                for license_info in component.get("licenses", []):
                    license_name = None
                    is_standard_format = False
                    if "license" in license_info:
                        lic = license_info["license"]
                        if "id" in lic:
                            license_name = lic["id"]
                            is_standard_format = True
                        elif "name" in lic:
                            name = lic["name"]
                            if (
                                name.startswith("License :: OSI Approved")
                                or "::" in name
                                or name in ["MIT", "Apache-2.0", "GPL-3.0-only", "BSD-3-Clause"]
                            ):
                                license_name = name
                                is_standard_format = True
                            elif (
                                not name.lower().startswith("declared license of")
                                and component.get("name", "---").lower() not in name.lower()
                            ):
                                license_name = name
                            else:
                                license_name = name
                                is_standard_format = False

                    if license_name:
                        if is_standard_format:
                            standard_licenses.append(license_name)
                        else:
                            descriptive_licenses.append(license_name)

                licenses_to_use = standard_licenses if standard_licenses else descriptive_licenses

                for license_name in licenses_to_use:
                    if not self.graph.has_node(license_name):
                        self.graph.add_node(
                            license_name,
                            type="LICENSE",
                            color=self.NODE_TYPES["LICENSE"]["color"],
                            size=self.NODE_TYPES["LICENSE"]["size"],
                            full_label=license_name,
                            abbreviated_label=self._get_abbreviated_label(license_name, "LICENSE"),
                        )
                    if self.graph.has_node(component_ref):
                        self.graph.add_edge(component_ref, license_name, relationship="license")

    def _process_dependencies(self, root_ref):
        """Process dependencies between components"""
        if not self.sbom_data or "dependencies" not in self.sbom_data:
            print("Warning: No 'dependencies' found in SBOM data.")
            return

        ref_to_node = dict(self.graph.nodes(data=True))
        print(f"DEBUG: Found {len(ref_to_node)} nodes in graph before processing dependencies.")

        edges_added_count = 0
        edges_skipped_missing_source = 0
        edges_skipped_missing_target = 0
        edges_skipped_license_target = 0

        dependencies_list = self.sbom_data.get("dependencies", [])
        print(f"DEBUG: Processing {len(dependencies_list)} entries in dependencies list.")

        for i, dep in enumerate(dependencies_list):
            source_ref = dep.get("ref")
            depends_on_list = dep.get("dependsOn", [])

            if (
                source_ref
                and source_ref in ref_to_node
                and self.graph.nodes[source_ref].get("type") != "LICENSE"
            ):
                if not self.graph.has_edge(root_ref, source_ref):
                    self.graph.add_edge(root_ref, source_ref, relationship="direct")
                    if edges_added_count < 20:
                        print(f"    DEBUG: Added ROOT edge: {root_ref} -> {source_ref}")
                    edges_added_count += 1
            if i < 5:
                print(
                    f"  DEBUG [Dep {i}]: Source Ref = '{source_ref}', DependsOn = {depends_on_list}"
                )

            if source_ref and source_ref in ref_to_node:
                for target_ref in depends_on_list:
                    if target_ref and target_ref in ref_to_node:
                        if ref_to_node[target_ref].get("type") != "LICENSE":
                            self.graph.add_edge(source_ref, target_ref, relationship="transitive")
                            edges_added_count += 1
                            if edges_added_count <= 10:
                                print(f"    DEBUG: Added edge: {source_ref} -> {target_ref}")
                        else:
                            edges_skipped_license_target += 1
                    else:
                        edges_skipped_missing_target += 1
                        if edges_skipped_missing_target <= 5:
                            print(
                                f"    DEBUG: Target '{target_ref}' not found for source '{source_ref}'. Skipping edge."
                            )
            elif source_ref:
                edges_skipped_missing_source += 1
                if edges_skipped_missing_source <= 5:
                    print(
                        f"  DEBUG [Dep {i}]: Source Ref '{source_ref}' not found in graph components. Skipping dependencies."
                    )

        print("DEBUG: Finished processing dependencies.")
        print(f"DEBUG: Edges Added: {edges_added_count}")
        print(f"DEBUG: Edges Skipped (Missing Source): {edges_skipped_missing_source}")
        print(f"DEBUG: Edges Skipped (Missing Target): {edges_skipped_missing_target}")
        print(f"DEBUG: Edges Skipped (License Target): {edges_skipped_license_target}")

    def graph_to_json(self):
        """Convert NetworkX graph to JSON format suitable for D3 hierarchical layout."""
        try:
            print("Starting graph to hierarchical JSON conversion...")

            print("Identifying vulnerable and dependent nodes...")
            vulnerable_nodes = set()

            for node_id, attrs in self.graph.nodes(data=True):
                attrs["isVulnerable"] = False
                if attrs.get("status") == "VULN" and attrs.get("type") != "LICENSE":
                    vulnerable_nodes.add(node_id)
                    attrs["isVulnerable"] = True

            print("Propagating dependent status...")
            all_ancestors_of_vulnerable = set()
            for vuln_node in vulnerable_nodes:
                try:
                    ancestors = nx.ancestors(self.graph, vuln_node)
                    all_ancestors_of_vulnerable.update(ancestors)
                except nx.NetworkXError as e:
                    print(f"  Warning: Could not find path for ancestors of {vuln_node}: {e}")

            dependent_nodes_count = 0
            for node_id in all_ancestors_of_vulnerable:
                if node_id not in vulnerable_nodes:
                    attrs = self.graph.nodes[node_id]
                    if attrs.get("type") != "LICENSE":
                        attrs["isDependentOnVulnerable"] = True
                        dependent_nodes_count += 1
                        if not attrs.get("isVulnerable"):
                            attrs["color"] = self.NODE_TYPES["LIBRARY"]["WEAK"]["color"]

            print(f"Marked {dependent_nodes_count} nodes as dependent on vulnerable components.")

            print(f"Total vulnerable nodes: {len(vulnerable_nodes)}")

            print("Identifying root node(s)...")
            root_ref = None
            for n, data in self.graph.nodes(data=True):
                if data.get("is_root"):
                    root_ref = n
                    break

            if root_ref:
                print(f"Using explicitly marked root: {root_ref}")
                root_nodes = [root_ref]
            else:
                print("No explicitly marked root found, determining root by in-degree...")
                potential_roots = []
                for n in self.graph.nodes():
                    if self.graph.nodes[n].get("type") == "LICENSE":
                        continue
                    has_lib_predecessor = False
                    for pred in self.graph.predecessors(n):
                        if self.graph.nodes[pred].get("type") != "LICENSE":
                            has_lib_predecessor = True
                            break
                    if not has_lib_predecessor:
                        potential_roots.append(n)

                if not potential_roots:
                    print(
                        "Warning: Could not determine a clear root by predecessors. Picking lowest in-degree library node."
                    )
                    min_degree = float("inf")
                    candidates = []
                    degree_dict = dict(self.graph.in_degree())
                    for n in self.graph.nodes():
                        if self.graph.nodes[n].get("type") == "LIBRARY":
                            degree = degree_dict[n]
                            if degree < min_degree:
                                min_degree = degree
                                candidates = [n]
                            elif degree == min_degree:
                                candidates.append(n)
                    if not candidates:
                        raise ValueError("Cannot determine any root node for the graph.")
                    root_nodes = candidates
                else:
                    root_nodes = potential_roots

            print(f"Identified root node(s): {root_nodes}")
            if len(root_nodes) > 1:
                print("Warning: Multiple root nodes found. Creating a dummy root.")
                sbom_metadata = self.sbom_data.get("metadata", {})  # type: ignore
                component_metadata = {}
                if sbom_metadata:
                    component_metadata = sbom_metadata.get("component", {})

                meta_ref = None
                if isinstance(component_metadata, dict):
                    meta_ref = component_metadata.get("bom-ref")
                    if not meta_ref:
                        meta_name = component_metadata.get("name", "Unknown")
                        meta_version = component_metadata.get("version", "latest")
                        meta_ref = f"{meta_name}=={meta_version}"
                if meta_ref and meta_ref in root_nodes:
                    print(f"Prioritizing metadata component {meta_ref} as primary root.")
                    root_json = self._build_hierarchy(meta_ref)
                else:
                    dummy_root_id = " VIRTUAL_ROOT "
                    root_json = {
                        "id": dummy_root_id,
                        "name": "Project Dependencies",
                        "fullLabel": "Project Dependencies",
                        "label": "Project",
                        "type": "SBOM",
                        "status": "DEFAULT",
                        "color": self.NODE_TYPES["SBOM"]["color"],
                        "size": self.NODE_TYPES["SBOM"]["size"],
                        "description": "Virtual root for multiple projects or components",
                        "isVulnerable": False,
                        "isDependentOnVulnerable": False,
                        "vulnerabilities": [],
                        "licenses": [],
                        "children": [self._build_hierarchy(root) for root in root_nodes],
                    }
            elif not root_nodes:
                raise ValueError("Failed to identify any root node.")
            else:
                root_json = self._build_hierarchy(root_nodes[0])

            # print("\n--- Generated Hierarchical JSON ---")
            # print(json.dumps(root_json, indent=2))
            # print("--- End Generated JSON ---\n")

            print("Hierarchical JSON conversion complete.")
            return root_json

        except Exception as e:
            print(f"Error in graph_to_json: {e}")
            import traceback

            print(traceback.format_exc())
            raise

    def _build_hierarchy(self, node_id, visited=None):
        """Recursively build the hierarchical structure for JSON output."""
        if visited is None:
            visited = set()

        if node_id in visited:
            node_attrs = self.graph.nodes[node_id]
            print(f"Cycle detected or node already visited: {node_id}. Stopping recursion here.")
            return {
                "id": str(node_id),
                "name": node_attrs.get("abbreviated_label", str(node_id)),
                "fullLabel": node_attrs.get("full_label", str(node_id)),
                "label": node_attrs.get("abbreviated_label", str(node_id)),
                "type": node_attrs.get("type", "LIBRARY"),
                "status": node_attrs.get("status", "DEFAULT"),
                "color": node_attrs.get("color", "#808080"),
                "size": node_attrs.get("size", 40),
                "description": node_attrs.get("description", ""),
                "isVulnerable": node_attrs.get("isVulnerable", False),
                "isDependentOnVulnerable": node_attrs.get("isDependentOnVulnerable", False),
                "vulnerabilities": self._get_vulnerability_info(node_id, node_attrs),
                "children": [],
                "isCycleReference": True,
            }

        visited.add(node_id)
        node_attrs = self.graph.nodes[node_id]

        child_dependencies = []
        child_licenses = []

        for successor in self.graph.successors(node_id):
            successor_attrs = self.graph.nodes[successor]
            if successor_attrs.get("type") == "LICENSE":
                child_licenses.append(
                    {
                        "id": str(successor),
                        "name": successor_attrs.get("abbreviated_label", str(successor)),
                        "fullLabel": successor_attrs.get("full_label", str(successor)),
                        "type": "LICENSE",
                        "color": successor_attrs.get("color", self.NODE_TYPES["LICENSE"]["color"]),
                        "size": successor_attrs.get("size", self.NODE_TYPES["LICENSE"]["size"]),
                    }
                )
            else:
                child_node = self._build_hierarchy(successor, visited.copy())
                if child_node:
                    child_dependencies.append(child_node)

        node_data = {
            "id": str(node_id),
            "name": node_attrs.get("abbreviated_label", str(node_id)),
            "fullLabel": node_attrs.get("full_label", str(node_id)),
            "label": node_attrs.get("abbreviated_label", str(node_id)),
            "type": node_attrs.get("type", "LIBRARY"),
            "status": node_attrs.get("status", "DEFAULT"),
            "color": node_attrs.get("color", "#808080"),
            "size": node_attrs.get("size", 40),
            "description": node_attrs.get("description", ""),
            "isVulnerable": node_attrs.get("isVulnerable", False),
            "isDependentOnVulnerable": node_attrs.get("isDependentOnVulnerable", False),
            "vulnerabilities": self._get_vulnerability_info(node_id, node_attrs),
            "licenses": child_licenses,
            "children": child_dependencies,
            "gnnPrediction": node_attrs.get("gnn_prediction", "Unknown"),
            "gnnConfidence": node_attrs.get("gnn_confidence", 0.0),
        }

        return node_data

    def _get_vulnerability_info(self, node_id, node_attrs):
        """Extract vulnerability details for a given node."""
        vulnerability_info = []
        if node_attrs.get("isVulnerable"):
            component = None
            if self.sbom_data and "components" in self.sbom_data:
                component = next(
                    (c for c in self.sbom_data["components"] if c.get("bom-ref") == node_id),
                    None,
                )
                if not component and "==" in node_id:
                    name, version = node_id.split("==", 1)
                    component = next(
                        (
                            c
                            for c in self.sbom_data["components"]
                            if c.get("name") == name and c.get("version") == version
                        ),
                        None,
                    )

            relevant_vulns_top_level = []
            if self.sbom_data and "vulnerabilities" in self.sbom_data:
                for vuln_item in self.sbom_data["vulnerabilities"]:
                    if "affects" in vuln_item:
                        for affect in vuln_item["affects"]:
                            if affect.get("ref") == node_id:
                                relevant_vulns_top_level.append(vuln_item)
                                break

            vuln_list_to_process = []
            if relevant_vulns_top_level:
                vuln_list_to_process = relevant_vulns_top_level
            elif component and "vulnerabilities" in component and component["vulnerabilities"]:
                vuln_list_to_process = component["vulnerabilities"]

            for vuln in vuln_list_to_process:
                vuln_id = vuln.get("cve_id") or vuln.get("source_id") or vuln.get("id", "Unknown")
                description = vuln.get("description", "No description available")
                recommendation = vuln.get("recommendation")
                published_date = vuln.get("published_date") or vuln.get("published")
                modified_date = vuln.get("modified_date") or vuln.get("updated")

                cvss_score = vuln.get("cvss_score")
                cvss_severity = vuln.get("cvss_severity", "Unknown")
                if cvss_severity is None:
                    cvss_severity = "Unknown"
                cvss_vector = vuln.get("cvss_vector", "N/A")
                if cvss_vector is None:
                    cvss_vector = "N/A"

                status = "unknown"
                if "analysis" in vuln and isinstance(vuln.get("analysis"), dict):
                    analysis_state = vuln["analysis"].get("state")
                    if analysis_state == "resolved" or analysis_state == "resolved_with_pedigree":
                        status = "fixed"
                    elif analysis_state == "exploitable":
                        status = "affected (exploitable)"
                    elif analysis_state in [
                        "in_triage",
                        "false_positive",
                        "not_affected",
                    ]:
                        status = analysis_state

                references = []
                ref_list = vuln.get("references") or vuln.get("advisories")
                if isinstance(ref_list, list):
                    references = [
                        ref.get("url")
                        for ref in ref_list
                        if isinstance(ref, dict) and ref.get("url")
                    ]

                fixed_versions = []
                if status == "fixed":
                    fixed_versions.append("Status: Fixed")
                elif recommendation and (
                    "upgrade" in recommendation.lower() or "update" in recommendation.lower()
                ):
                    fixed_versions.append("See recommendation")

                vulnerability_info.append(
                    {
                        "id": vuln_id,
                        "source": vuln.get("source", {}).get("name", "N/A"),
                        "description": description,
                        "recommendation": recommendation,
                        "status": status,
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "cvss_vector": cvss_vector,
                        "references": references,
                        "published": published_date,
                        "updated": modified_date,
                        "fixed_versions": fixed_versions,
                    }
                )

        return vulnerability_info
