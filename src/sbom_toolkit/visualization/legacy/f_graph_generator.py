"""
This module provides functionality to generate a graph visualization of a Software Bill of Materials (SBOM).
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


class SBOMGraph:
    """Generate a graph visualization of a Software Bill of Materials (SBOM).

    This class provides functionality to create a graph visualization of a
    Software Bill of Materials (SBOM). It allows for the generation of a graph
    representation of the SBOM, including nodes and edges representing components,
    dependencies, and licenses.

    Attributes:
        graph (nx.Graph): The NetworkX graph object.
        NODE_TYPES (dict): A dictionary defining the types of nodes and their associated styles.
        sbom_data (dict): The SBOM data loaded from a JSON file.
    """

    def __init__(self):
        """Initialize the SBOMGraph object."""
        self.graph = nx.Graph()
        self.NODE_TYPES: dict[str, Any] = {
            "SBOM": {"color": "#808080", "size": 80},  # Grey
            "LIBRARY": {
                "SAFE": {"color": "#7FD13B", "size": 40},  # Green (Unused directly now)
                "WEAK": {"color": "#FFA500", "size": 40},  # Orange (Now Yellow Fill)
                "VULN": {"color": "#FF5252", "size": 40},  # Red Fill
                "DEFAULT": {"color": "#4169E1", "size": 40},  # Blue Fill (Default)
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

    def _calculate_node_layers(self):
        """Calculate layer number for each node based on vulnerability status and dependencies"""
        nx.set_node_attributes(self.graph, float("inf"), "layer")

        if not self.sbom_data:
            print("Warning: SBOM data not loaded before calculating layers.")
            return

        metadata = self.sbom_data.get("metadata", {})
        component = metadata.get("component", {})
        if not isinstance(component, dict):
            component = {}

        root_ref = component.get("bom-ref")
        root_name = component.get("name", "Unknown Project")
        root_version = component.get("version", "N/A")

        if root_name == "Unknown Project" or not root_name:
            repo_info = metadata.get("repository", {})
            if isinstance(repo_info, dict) and repo_info.get("name"):
                root_name = repo_info["name"]

        if not root_ref:
            root_ref = f"{root_name}=={root_version}"

        vulnerable_nodes = set()
        dependent_nodes = set()
        for node, attrs in self.graph.nodes(data=True):
            if attrs and attrs.get("status") == "VULN":
                vulnerable_nodes.add(node)
                for neighbor in self.graph.neighbors(node):
                    if (
                        self.graph.has_node(neighbor)
                        and self.graph.nodes[neighbor].get("type") != "LICENSE"
                    ):
                        dependent_nodes.add(neighbor)

        for node, attrs in self.graph.nodes(data=True):
            if not attrs:
                continue

            if node == root_ref:
                attrs["layer"] = 0
            elif attrs.get("type") == "LICENSE":
                attrs["layer"] = 4
            elif node in vulnerable_nodes:
                attrs["layer"] = 1
                attrs["status"] = "VULN"  # Ensure status is explicitly VULN
                attrs["color"] = self.NODE_TYPES["LIBRARY"]["VULN"]["color"]
            elif node in dependent_nodes:
                attrs["layer"] = 2
                attrs["status"] = "WEAK"  # Use WEAK status for dependent
                attrs["color"] = self.NODE_TYPES["LIBRARY"]["WEAK"]["color"]
            else:
                if attrs.get("layer") == float("inf"):  # Only update if not already set
                    attrs["layer"] = 3
                    attrs["status"] = "DEFAULT"  # Explicitly default
                    attrs["color"] = self.NODE_TYPES["LIBRARY"]["DEFAULT"]["color"]

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

        root_ref = component.get("bom-ref")
        root_name = component.get("name", "Unknown Project")
        root_version = component.get("version", "N/A")

        if root_name == "Unknown Project" or not root_name:
            repo_info = metadata.get("repository", {})
            if isinstance(repo_info, dict) and repo_info.get("name"):
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
        )

        self._process_components()
        self._process_dependencies(root_ref)

        # --- Add GNN Predictions ---
        print("Attempting to add GNN predictions...")
        predictions = {}  # Skip GNN predictions for now to debug core functionality
        if GNN_AVAILABLE and False:  # Temporarily disabled
            # Specify the correct path to the model
            model_file_path = Path("out/model/best_model.pt")
            predictions = predict_sbom(sbom_path=sbom_file, model_path=model_file_path)
            if predictions is None:
                print("Warning: GNN prediction failed or returned None. Skipping GNN attributes.")
                # Set default values for all library nodes if prediction fails
                predictions = {}  # Ensure predictions is an empty dict to prevent errors below
            else:
                print(f"Received {len(predictions)} GNN predictions.")
                # --- Debug: Print Prediction Keys ---
                if len(predictions) < 100:  # Print keys only if not too many
                    print(f"  Prediction keys ({len(predictions)}): {list(predictions.keys())}")
                else:
                    print(
                        f"  Prediction keys ({len(predictions)}): {[key for i, key in enumerate(predictions.keys()) if i < 20]}..."
                    )  # Print first 20
                # --- End Debug ---

        # Apply predictions or defaults
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "LIBRARY":
                # --- Debug Logging Start ---
                actual_status = node_data.get("status", "UNKNOWN")  # Status based on SBOM scan
                prediction = predictions.get(node_id)
                if prediction:
                    node_data["gnn_prediction"] = prediction.get("prediction", "Unknown")
                    node_data["gnn_confidence"] = prediction.get("confidence", 0.0)
                    # Log comparison
                    if actual_status == "VULN" and node_data["gnn_prediction"] == "Non-Vulnerable":
                        print(
                            f"  [MISMATCH] Node: {node_id}, Actual: {actual_status}, GNN: {node_data['gnn_prediction']}"
                        )
                    elif actual_status != "VULN" and node_data["gnn_prediction"] == "Vulnerable":
                        print(
                            f"  [MISMATCH] Node: {node_id}, Actual: {actual_status}, GNN: {node_data['gnn_prediction']}"
                        )
                    # else: # Optional: Log matches too
                    #    print(f"  [MATCH] Node: {node_id}, Actual: {actual_status}, GNN: {node_data['gnn_prediction']}")
                else:
                    # Set default if node_id not found in predictions
                    node_data["gnn_prediction"] = "Unknown"
                    node_data["gnn_confidence"] = 0.0
                    print(f"  [NO PREDICTION] Node: {node_id}, Actual: {actual_status}")
                # --- Debug Logging End ---

        self._calculate_node_layers()

    def _get_component_status(self, component):
        """Determine component status based on vulnerabilities"""
        if "vulnerabilities" in component and component["vulnerabilities"]:
            return "VULN"
        return "DEFAULT"

    def _process_components(self):
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

            # Determine initial status based ONLY on own vulnerabilities for now
            # Dependent status will be set later in _calculate_node_layers
            status = self._get_component_status(component)
            node_style = self.NODE_TYPES["LIBRARY"][status]
            color = node_style["color"]  # Get color based on initial status

            if self.graph.has_node(component_ref):
                full_label = (
                    f"{component.get('name', 'Unknown')}=={component.get('version', 'latest')}"
                )
                # Update existing node, but be careful not to overwrite dependent status later
                self.graph.nodes[component_ref].update(
                    {
                        "status": status,  # Update initial status
                        "color": color,  # Update initial color
                        "size": node_style["size"],
                        "full_label": full_label,
                        "abbreviated_label": self._get_abbreviated_label(full_label, "LIBRARY"),
                        "description": component.get("description", ""),
                    }
                )
            else:
                full_label = (
                    f"{component.get('name', 'Unknown')}=={component.get('version', 'unknown')}"
                )
                self.graph.add_node(
                    component_ref,
                    type="LIBRARY",
                    status=status,
                    color=color,  # Set initial color
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
                        # Check if edge already exists before adding (less likely in Graph, good practice)
                        if not self.graph.has_edge(component_ref, license_name):
                            self.graph.add_edge(
                                component_ref,
                                license_name,
                                weight=1,
                                color="#a8a8a8",
                                relationship="license",
                            )

    def _process_dependencies(self, root_ref):
        """Process dependencies between components"""
        if not self.sbom_data or "dependencies" not in self.sbom_data:
            print("Warning: No 'dependencies' found in SBOM data.")
            print("Creating fallback visualization with license-based clustering...")
            self._create_fallback_structure()
            return

        for dep in self.sbom_data.get("dependencies", []):
            source_ref = dep.get("ref")
            if not source_ref:
                continue

            if not self.graph.has_node(source_ref):
                print(
                    f"Warning: Source dependency '{source_ref}' not found in components. Skipping edges."
                )
                continue

            # Add edge from root only if source is not a license and edge doesn't exist
            if (
                self.graph.nodes[source_ref].get("type") != "LICENSE"
                and source_ref != root_ref
                and self.graph.has_node(root_ref)
            ):
                if not self.graph.has_edge(root_ref, source_ref):
                    self.graph.add_edge(
                        root_ref,
                        source_ref,
                        weight=2,
                        color="#a8a8a8",
                        relationship="direct",
                    )

            depends_on_list = dep.get("dependsOn", [])
            if depends_on_list:
                for target_ref in depends_on_list:
                    if not target_ref:
                        continue

                    if self.graph.has_node(target_ref) and source_ref != target_ref:
                        if self.graph.nodes[target_ref].get("type") != "LICENSE":
                            # Check if edge already exists before adding
                            if not self.graph.has_edge(source_ref, target_ref):
                                self.graph.add_edge(
                                    source_ref,
                                    target_ref,
                                    weight=1,
                                    color="#a8a8a8",
                                    relationship="transitive",
                                )
                    elif not self.graph.has_node(target_ref):
                        print(
                            f"Warning: Target dependency '{target_ref}' not found for source '{source_ref}'. Skipping edge."
                        )

    def _create_fallback_structure(self):
        """Create a fallback visualization structure when dependencies are missing."""
        # Group components by common licenses to create some visual structure
        license_groups = {}
        components_without_licenses = []

        for node_id, attrs in self.graph.nodes(data=True):
            if attrs.get("type") == "LIBRARY":
                # Find license nodes connected to this component
                connected_licenses = []
                for neighbor in self.graph.neighbors(node_id):
                    if self.graph.nodes[neighbor].get("type") == "LICENSE":
                        connected_licenses.append(neighbor)

                if connected_licenses:
                    # Group by first license (simple heuristic)
                    license_key = connected_licenses[0]
                    if license_key not in license_groups:
                        license_groups[license_key] = []
                    license_groups[license_key].append(node_id)
                else:
                    components_without_licenses.append(node_id)

        # Create connections between components that share licenses
        connections_created = 0
        for _license_name, components in license_groups.items():
            if len(components) > 1:
                # Connect components that share this license
                for i, comp1 in enumerate(components):
                    for comp2 in components[i + 1 :]:
                        if not self.graph.has_edge(comp1, comp2):
                            self.graph.add_edge(
                                comp1,
                                comp2,
                                weight=0.5,
                                color="#666666",
                                relationship="license_group",
                            )
                            connections_created += 1

        # If no license-based connections were created, create a simple star pattern
        # Connect the first component (root) to a few others for basic visualization
        if connections_created == 0 and len(components_without_licenses) > 1:
            root_component = components_without_licenses[0]
            for comp in components_without_licenses[1:6]:  # Connect to first 5 components
                if not self.graph.has_edge(root_component, comp):
                    self.graph.add_edge(
                        root_component,
                        comp,
                        weight=0.3,
                        color="#999999",
                        relationship="fallback",
                    )
                    connections_created += 1

        print(
            f"Created fallback structure with {len(license_groups)} license groups and {connections_created} connections"
        )

    def graph_to_json(self):
        """Convert NetworkX graph to JSON format for D3"""
        try:
            print("Starting graph to JSON conversion...")
            vulnerable_nodes = set()
            vulnerable_connections = set()
            dependent_nodes = set()
            dependent_connections = set()

            print("Finding vulnerable nodes...")
            for node, attrs in self.graph.nodes(data=True):
                if attrs and attrs.get("status") == "VULN" and attrs.get("type") != "LICENSE":
                    vulnerable_nodes.add(node)

            print(f"Found {len(vulnerable_nodes)} vulnerable nodes")

            print("Finding vulnerable connections...")
            for source, target, _attrs in self.graph.edges(data=True):
                if not self.graph.has_node(source) or not self.graph.has_node(target):
                    continue
                source_is_vuln = source in vulnerable_nodes
                target_is_vuln = target in vulnerable_nodes

                if (
                    source_is_vuln
                    and not target_is_vuln
                    and self.graph.nodes[target].get("type") != "LICENSE"
                ) or (
                    target_is_vuln
                    and not source_is_vuln
                    and self.graph.nodes[source].get("type") != "LICENSE"
                ):
                    vulnerable_connections.add(tuple(sorted((source, target))))

            print(f"Found {len(vulnerable_connections)} vulnerable connections")

            print("Finding dependent nodes...")

            for node, attrs in self.graph.nodes(data=True):
                if not attrs or attrs.get("type") == "LICENSE" or node in vulnerable_nodes:
                    continue

                for neighbor in self.graph.neighbors(node):
                    if neighbor in vulnerable_nodes:
                        edge_data = self.graph.get_edge_data(node, neighbor)
                        if edge_data and edge_data.get("relationship") != "license":
                            dependent_nodes.add(node)
                            dependent_connections.add(tuple(sorted((node, neighbor))))
                            break

            print(f"Found {len(dependent_nodes)} dependent nodes")
            print(f"Found {len(dependent_connections)} dependent connections")

            print("Creating nodes list...")
            nodes = []
            component_vulnerabilities = {}

            if self.sbom_data and "vulnerabilities" in self.sbom_data:
                print("Processing top-level vulnerabilities...")
                for vuln in self.sbom_data["vulnerabilities"]:
                    if "affects" in vuln:
                        for affect in vuln["affects"]:
                            ref = affect.get("ref")
                            if ref:
                                if ref not in component_vulnerabilities:
                                    component_vulnerabilities[ref] = []
                                component_vulnerabilities[ref].append(
                                    {
                                        "id": vuln.get("id", vuln.get("source_id", "Unknown")),
                                        "source_id": vuln.get(
                                            "source_id", vuln.get("id", "Unknown")
                                        ),
                                        "cve_id": vuln.get("cve_id", "Unknown"),
                                        "published_date": vuln.get("published_date"),
                                        "modified_date": vuln.get("modified_date"),
                                        "description": vuln.get(
                                            "description", "No description available"
                                        ),
                                        "cvss_score": vuln.get("cvss_score"),
                                        "cvss_severity": vuln.get("cvss_severity"),
                                        "cvss_vector": vuln.get("cvss_vector"),
                                        "references": vuln.get("references", []),
                                        "affected_versions": vuln.get(
                                            "affected_versions", ["Unknown"]
                                        ),
                                        "fixed_versions": vuln.get("fixed_versions", ["Unknown"]),
                                    }
                                )
                print(
                    f"Processed vulnerabilities for {len(component_vulnerabilities)} components from top-level list."
                )

            # Pre-calculate dependent nodes again to ensure status consistency
            dependent_nodes_recalc = set()
            for node_id, attrs in self.graph.nodes(data=True):
                if not attrs or attrs.get("type") == "LICENSE" or node_id in vulnerable_nodes:
                    continue
                for neighbor in self.graph.neighbors(node_id):
                    if neighbor in vulnerable_nodes:
                        edge_data = self.graph.get_edge_data(node_id, neighbor)
                        if edge_data and edge_data.get("relationship") != "license":
                            dependent_nodes_recalc.add(node_id)
                            break  # Only need one vulnerable neighbor

            print(f"Recalculated dependent nodes for JSON: {len(dependent_nodes_recalc)}")

            for node_id, attrs in self.graph.nodes(data=True):
                if not attrs:
                    continue

                is_license = attrs.get("type") == "LICENSE"
                # Status should be determined based on calculation, not just checking vulnerable_nodes set
                is_vulnerable = attrs.get("status") == "VULN" and not is_license
                is_dependent = attrs.get("status") == "WEAK" and not is_license  # Use 'WEAK' status

                # Ensure the color reflects the final status
                node_color = attrs.get("color", "#808080")  # Default grey
                if is_vulnerable:
                    node_color = self.NODE_TYPES["LIBRARY"]["VULN"]["color"]
                elif is_dependent:
                    node_color = self.NODE_TYPES["LIBRARY"]["WEAK"]["color"]
                elif (
                    not is_license
                ):  # If not vuln, not dependent, and not license, it's default/safe
                    node_color = self.NODE_TYPES["LIBRARY"]["DEFAULT"]["color"]
                elif is_license:
                    node_color = self.NODE_TYPES["LICENSE"]["color"]

                vulnerability_info = []
                if is_vulnerable:
                    vulnerability_info = component_vulnerabilities.get(node_id, [])
                    if not vulnerability_info:
                        component = next(
                            (
                                c
                                for c in self.sbom_data.get("components", [])  # type: ignore
                                if c.get("bom-ref") == node_id
                                or f"{c.get('name')}=={c.get('version')}" == node_id
                            ),
                            None,
                        )
                        if component and "vulnerabilities" in component:
                            for vuln in component["vulnerabilities"]:
                                vulnerability_info.append(
                                    {
                                        "id": vuln.get("id", vuln.get("source_id", "Unknown")),
                                        "source_id": vuln.get(
                                            "source_id", vuln.get("id", "Unknown")
                                        ),
                                        "cve_id": vuln.get("cve_id", "Unknown"),
                                        "published_date": vuln.get("published_date"),
                                        "modified_date": vuln.get("modified_date"),
                                        "description": vuln.get(
                                            "description", "No description available"
                                        ),
                                        "cvss_score": vuln.get("cvss_score"),
                                        "cvss_severity": vuln.get("cvss_severity"),
                                        "cvss_vector": vuln.get("cvss_vector"),
                                        "references": vuln.get("references", []),
                                        "affected_versions": vuln.get(
                                            "affected_versions", ["Unknown"]
                                        ),
                                        "fixed_versions": vuln.get("fixed_versions", ["Unknown"]),
                                    }
                                )

                nodes.append(
                    {
                        "id": str(node_id),
                        "fullLabel": attrs.get("full_label", str(node_id)),
                        "label": attrs.get("abbreviated_label", str(node_id)),
                        "type": attrs.get("type", "LIBRARY"),
                        "status": attrs.get("status", "DEFAULT"),
                        "color": node_color,  # Use the recalculated color
                        "size": attrs.get("size", 40),
                        "layer": attrs.get("layer", 0),
                        "description": attrs.get("description", ""),
                        "isVulnerable": is_vulnerable,
                        "isDependent": is_dependent,
                        "vulnerabilities": vulnerability_info,
                        # --- Add GNN Prediction Data ---
                        "gnnPrediction": attrs.get("gnn_prediction", "Unknown"),
                        "gnnConfidence": attrs.get("gnn_confidence", 0.0),
                        # --- End GNN Prediction Data ---
                    }
                )

            print("Creating links list...")
            links = []
            processed_edges = set()
            for source, target, attrs in self.graph.edges(data=True):
                edge_tuple = tuple(sorted((str(source), str(target))))
                if edge_tuple in processed_edges:
                    continue
                processed_edges.add(edge_tuple)

                is_vulnerable_connection = edge_tuple in vulnerable_connections
                is_dependent_connection = edge_tuple in dependent_connections

                edge_color = attrs.get("color", "#a8a8a8")
                if is_dependent_connection:
                    edge_color = "#FFA500"
                elif is_vulnerable_connection:
                    edge_color = "#FF5252"

                links.append(
                    {
                        "source": str(source),
                        "target": str(target),
                        "weight": attrs.get("weight", 1),
                        "color": edge_color,
                        "relationship": attrs.get("relationship", "unknown"),
                        "isVulnerableConnection": is_vulnerable_connection,
                        "isDependentConnection": is_dependent_connection,
                    }
                )

            print("Graph conversion complete")
            return {"nodes": nodes, "links": links}

        except Exception as e:
            print(f"Error in graph_to_json: {e}")
            import traceback

            print(traceback.format_exc())
            return {"nodes": [], "links": []}
