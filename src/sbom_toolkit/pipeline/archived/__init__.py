"""
Archived functionality for the SBOM toolkit pipeline.

This module contains functionality that has been moved from active use but
preserved for future development or reference.

Note: Code in this module is not actively maintained or tested.
"""

# Archived Docker functionality
from .docker_tools import generate_sbom_with_docker

__all__ = [
    "generate_sbom_with_docker",
]
