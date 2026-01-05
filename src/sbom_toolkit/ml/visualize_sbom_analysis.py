import json
import os
from collections import defaultdict

# Optional dependencies with graceful fallbacks
try:
    import matplotlib.pyplot as plt
    import pandas as pd

    DEPS_AVAILABLE = True
except ImportError:
    DEPS_AVAILABLE = False
    plt = None  # type: ignore[assignment]
    pd = None  # type: ignore[assignment]

# Check if required dependencies are available
if not DEPS_AVAILABLE:
    raise ImportError(
        "Missing required dependencies for SBOM visualization. "
        "Install with: pip install matplotlib pandas"
    )


def analyze_sbom_files(directory):
    data = []
    severity_counts = defaultdict(int)

    for filename in os.listdir(directory):
        if filename.endswith("_enriched"):
            filepath = os.path.join(directory, filename)
            with open(filepath) as f:
                try:
                    sbom = json.load(f)
                    # Count components (nodes)
                    node_count = len(sbom.get("components", []))

                    # Count dependencies (edges) from the dependencies section
                    edge_count = 0
                    for dep in sbom.get("dependencies", []):
                        edge_count += len(dep.get("dependsOn", []))

                    # Count vulnerabilities and their severities
                    vuln_count = 0
                    for component in sbom.get("components", []):
                        for vuln in component.get("vulnerabilities", []):
                            vuln_count += 1
                            severity = vuln.get("cvss_severity")
                            # Handle None or missing severity
                            if severity is None or severity == "":
                                severity = "UNKNOWN"
                            severity_counts[severity] += 1

                    data.append(
                        {
                            "sbom_id": filename.split("_")[0],
                            "node_count": node_count,
                            "edge_count": edge_count,
                            "vuln_count": vuln_count,
                        }
                    )
                except json.JSONDecodeError:
                    print(f"Error reading {filename}")

    return pd.DataFrame(data), severity_counts


def create_visualizations(df, severity_counts):
    # Create figure with 2x2 subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))

    # Plot 1: Distribution of Graph Sizes (Nodes)
    ax1.hist(df["node_count"], bins=30, color="skyblue", edgecolor="black")
    ax1.set_xlabel("Number of Components (Nodes) per SBOM")
    ax1.set_ylabel("Frequency (Number of SBOMs)")
    ax1.set_title("Distribution of Project Sizes (Component Count)")
    ax1.grid(True, alpha=0.3)

    # Plot 2: Distribution of Graph Sizes (Edges)
    ax2.hist(df["edge_count"], bins=30, color="lightgreen", edgecolor="black")
    ax2.set_xlabel("Number of Dependencies (Edges) per SBOM")
    ax2.set_ylabel("Frequency (Number of SBOMs)")
    ax2.set_title("Distribution of Dependency Counts")
    ax2.grid(True, alpha=0.3)

    # Plot 3: Distribution of Vulnerabilities
    ax3.hist(df["vuln_count"], bins=30, color="salmon", edgecolor="black")
    ax3.set_xlabel("Number of Vulnerabilities per SBOM")
    ax3.set_ylabel("Frequency (Number of SBOMs)")
    ax3.set_title("Distribution of Vulnerabilities per Project")
    ax3.grid(True, alpha=0.3)

    # Plot 4: Distribution of Vulnerability Severities
    # Define order of severities from highest to lowest
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    counts = [severity_counts.get(sev, 0) for sev in severity_order]
    colors = ["darkred", "red", "orange", "yellow", "gray"]

    bars = ax4.bar(severity_order, counts, color=colors)
    ax4.set_xlabel("Vulnerability Severity")
    ax4.set_ylabel("Number of Vulnerabilities")
    ax4.set_title("Distribution of Vulnerability Severities")
    ax4.grid(True, alpha=0.3, axis="y")

    # Add value labels on top of each bar
    for bar in bars:
        height = bar.get_height()
        ax4.text(
            bar.get_x() + bar.get_width() / 2.0,
            height,
            f"{int(height)}",
            ha="center",
            va="bottom",
        )

    # Adjust layout and save
    plt.tight_layout()
    output_path = os.path.join("outputs", "sbom_analysis.png")
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()


def main():
    sbom_dir = "scanned_sboms"
    df, severity_counts = analyze_sbom_files(sbom_dir)
    create_visualizations(df, severity_counts)

    # Print statistics
    print("\nSBOM Analysis Statistics:")
    print(f"Total SBOMs analyzed: {len(df)}")

    print("\nNode Count Statistics:")
    print(df["node_count"].describe())

    print("\nDependency Count Statistics:")
    print(df["edge_count"].describe())

    print("\nVulnerability Count Statistics:")
    print(df["vuln_count"].describe())

    print("\nVulnerability Severity Distribution:")
    # Use predefined order for consistent output
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        print(f"{severity}: {count}")


if __name__ == "__main__":
    main()
