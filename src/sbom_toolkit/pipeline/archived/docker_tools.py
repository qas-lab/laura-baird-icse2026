"""
Archived Docker-based SBOM generation tools.

These tools were moved from active use but are preserved for future development.
Docker-based generation provides clean environment isolation but requires Docker + Syft.

Note: This functionality is archived and not actively maintained or tested.
"""

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from ...shared.exceptions import SBOMGenerationError, create_error_context
from ...shared.models import RepositoryInfo
from ...shared.version import detect_python_version


def generate_sbom_with_docker(repo_info: RepositoryInfo, output_dir: Path) -> Path | None:
    """Generate SBOM using Docker for clean dependency isolation.

    ARCHIVED: This function is no longer actively used but preserved for future development.
    """
    if not (shutil.which("docker") and shutil.which("syft")):
        raise SBOMGenerationError(
            "Docker and Syft required for Docker-based generation",
            create_error_context(operation="docker_check"),
        )

    logger = logging.getLogger(__name__)
    logger.info(f"Generating SBOM using Docker for {repo_info.metadata.name}")

    output_filename = f"{repo_info.metadata.name}_sbom.json"
    sbom_path = output_dir / output_filename

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Copy source (excluding venv, git, etc.)
        _copy_source_for_docker(repo_info.path, temp_path)

        # Create Dockerfile
        dockerfile = temp_path / "Dockerfile"
        python_version = detect_python_version(repo_info.path)

        with open(dockerfile, "w") as f:
            f.write(
                f"""
FROM python:{python_version}-slim
WORKDIR /app
COPY . .
RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
RUN if [ -f pyproject.toml ]; then pip install .; fi
""".strip()
            )

        # Build image
        image_name = f"sbom-scan-{repo_info.metadata.name.lower()}"
        subprocess.run(
            ["docker", "build", "-t", image_name, str(temp_path)],
            check=True,
            capture_output=True,
            timeout=600,
        )

        try:
            # Scan with Syft
            subprocess.run(
                ["syft", f"docker:{image_name}", "-o", f"cyclonedx-json={sbom_path}"],
                check=True,
                capture_output=True,
                timeout=300,
            )

            # Cleanup
            subprocess.run(["docker", "rmi", "-f", image_name], check=False, capture_output=True)

            # Enrich metadata - would need to import/copy this function
            # _enrich_sbom_metadata(sbom_path, repo_info, "docker+syft")
            return sbom_path

        except Exception:
            # Cleanup on failure
            subprocess.run(["docker", "rmi", "-f", image_name], check=False, capture_output=True)
            raise


def _copy_source_for_docker(src: Path, dest: Path) -> None:
    """Copy source code excluding unnecessary files for Docker build.

    ARCHIVED: This function is no longer actively used but preserved for future development.
    """
    import shutil

    exclude_patterns = {
        ".git",
        "__pycache__",
        "*.pyc",
        ".venv",
        "venv",
        ".env",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        "*.log",
        ".DS_Store",
        "Thumbs.db",
    }

    def should_exclude(path: Path) -> bool:
        for pattern in exclude_patterns:
            if pattern in str(path) or path.name.startswith("."):
                return True
        return False

    for item in src.iterdir():
        if not should_exclude(item):
            dest_item = dest / item.name
            if item.is_dir():
                shutil.copytree(item, dest_item, ignore=shutil.ignore_patterns(*exclude_patterns))
            else:
                shutil.copy2(item, dest_item)


def _detect_python_version(repo_path: Path) -> str:
    """Detect Python version for Docker build.

    ARCHIVED: This function is no longer actively used but preserved for future development.
    """
    # Check .python-version file
    python_version_file = repo_path / ".python-version"
    if python_version_file.exists():
        version = python_version_file.read_text().strip()
        if version:
            return version

    # Check pyproject.toml
    pyproject_file = repo_path / "pyproject.toml"
    if pyproject_file.exists():
        import re

        content = pyproject_file.read_text()
        match = re.search(r'python\s*=\s*["\']([^"\']+)["\']', content)
        if match:
            version_spec = match.group(1)
            # Extract version number from spec like ">=3.9,<4.0"
            version_match = re.search(r"(\d+\.\d+)", version_spec)
            if version_match:
                return version_match.group(1)

    # Default
    return "3.11"
