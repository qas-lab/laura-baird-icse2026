"""
SBOM Visualization Module

This module provides unified interactive visualization capabilities for Software Bill of Materials (SBOM)
data with multiple layout types and a modern interface with sidebar controls.
"""

# New unified visualization system
from .unified import (
    create_d3_visualization,  # Backward compatibility
    create_unified_visualization,
    get_available_layouts,
    validate_sbom_file,
)

# Legacy imports for backward compatibility
try:
    from .d3_visualizer import D3Visualizer  # noqa: F401
    from .legacy.f_graph_generator import SBOMGraph  # noqa: F401
    from .legacy.h_graph_generator import HierarchicalSBOMGraph  # noqa: F401

    LEGACY_AVAILABLE = True
except ImportError:
    LEGACY_AVAILABLE = False

# Core components
from .core import SBOMDataTransformer, UnifiedVisualizer
from .engines import CircularEngine, ForceDirectedEngine, HierarchicalEngine

__all__ = [
    # Primary unified interface
    "create_unified_visualization",
    "get_available_layouts",
    "validate_sbom_file",
    # Core components
    "UnifiedVisualizer",
    "SBOMDataTransformer",
    "ForceDirectedEngine",
    "HierarchicalEngine",
    "CircularEngine",
    # Backward compatibility
    "create_d3_visualization",
]

# Add legacy exports if available
if LEGACY_AVAILABLE:
    __all__.extend(["D3Visualizer", "SBOMGraph", "HierarchicalSBOMGraph"])
