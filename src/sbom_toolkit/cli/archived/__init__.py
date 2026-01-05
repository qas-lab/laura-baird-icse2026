"""
Archived CLI commands for the SBOM toolkit.

.. deprecated::
    This module contains CLI commands that have been moved from active use but
    preserved for future development or reference.
    Commands in this module are not actively maintained or tested.
"""

import warnings

from .completion import completion
from .validate import validate_generation, validate_visualization

warnings.warn(
    "sbom_toolkit.cli.archived contains deprecated commands. "
    "These may be removed or refactored in future versions.",
    DeprecationWarning,
    stacklevel=2,
)

# Archive validation commands that need refactoring due to Docker dependency removal
# Archive completion command for future shell completion work

__all__ = [
    "validate_generation",
    "validate_visualization",
    "completion",
]
