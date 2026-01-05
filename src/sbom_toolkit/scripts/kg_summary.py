#!/usr/bin/env python3
"""
Standalone Knowledge Graph Summary Script

This script can be run independently to generate summaries of knowledge graphs.
It provides the same functionality as the CLI command but as a standalone tool.

Usage:
    python -m sbom_toolkit.scripts.kg_summary path/to/knowledge_graph.json
    python -m sbom_toolkit.scripts.kg_summary path/to/knowledge_graph.json --visualize
    python -m sbom_toolkit.scripts.kg_summary path/to/knowledge_graph.json --details --json-output summary.json
"""

from ..cli.commands.kg_summary import kg_summary_command

if __name__ == "__main__":
    kg_summary_command()
