#!/usr/bin/env python3
"""Download dataset from Harvard Dataverse.

Downloads and extracts the SBOM Toolkit dataset archives.
"""

import hashlib
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# Configuration - Update these after publishing to Dataverse
DATAVERSE_DOI = "10.7910/DVN/A6CZRB"
DATAVERSE_BASE_URL = "https://dataverse.harvard.edu/api/access/datafile"

# File IDs will be assigned after upload - Update these values
# To find file IDs: Go to dataset page -> Files tab -> hover over download button
DATAVERSE_FILES: dict[str, dict[str, str | int]] = {
    "sboms.tar.gz": {
        "file_id": 0,  # Update after upload
        "sha256": "",  # Update after upload
        "description": "Software Bills of Materials",
    },
    "scans.tar.gz": {
        "file_id": 0,
        "sha256": "",
        "description": "Vulnerability scan results",
    },
    "models.tar.gz": {
        "file_id": 0,
        "sha256": "",
        "description": "Trained model checkpoints",
    },
    "evaluations.tar.gz": {
        "file_id": 0,
        "sha256": "",
        "description": "Evaluation results",
    },
    "reference_data.tar.gz": {
        "file_id": 0,
        "sha256": "",
        "description": "Reference data and caches",
    },
}

PROJECT_ROOT = Path(__file__).parent.parent


def compute_sha256(filepath: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with filepath.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def download_file(url: str, dest: Path, description: str) -> bool:
    """Download a file with progress indication."""
    print(f"  Downloading {description}...")

    try:
        urllib.request.urlretrieve(url, dest)
        return True
    except urllib.error.URLError as e:
        print(f"  Error downloading: {e}")
        return False


def verify_checksum(filepath: Path, expected_sha256: str) -> bool:
    """Verify file checksum."""
    if not expected_sha256:
        print("  Warning: No checksum available, skipping verification")
        return True

    actual = compute_sha256(filepath)
    if actual != expected_sha256:
        print("  Checksum mismatch!")
        print(f"    Expected: {expected_sha256}")
        print(f"    Got:      {actual}")
        return False
    print("  Checksum verified")
    return True


def extract_archive(archive_path: Path, dest_dir: Path) -> bool:
    """Extract tar.gz archive."""
    print(f"  Extracting to {dest_dir}...")
    try:
        subprocess.run(
            ["tar", "-xzf", str(archive_path), "-C", str(dest_dir)],
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"  Error extracting: {e.stderr.decode()}")
        return False


def download_from_dataverse(
    files: list[str] | None = None,
    extract: bool = True,
    verify: bool = True,
) -> int:
    """Download dataset files from Harvard Dataverse.

    Args:
        files: List of specific files to download, or None for all
        extract: Whether to extract archives after download
        verify: Whether to verify checksums

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # Check if file IDs are configured
    if all(info["file_id"] == 0 for info in DATAVERSE_FILES.values()):
        print("Error: Dataverse file IDs not configured.")
        print("")
        print("This script needs to be updated after the dataset is published.")
        print("Please either:")
        print("  1. Download files manually from: https://doi.org/" + DATAVERSE_DOI)
        print("  2. Update DATAVERSE_FILES in this script with actual file IDs")
        return 1

    files_to_download = files or list(DATAVERSE_FILES.keys())

    print("SBOM Toolkit Dataset Downloader")
    print(f"Dataset DOI: {DATAVERSE_DOI}")
    print("=" * 50)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        success_count = 0

        for filename in files_to_download:
            if filename not in DATAVERSE_FILES:
                print(f"\nUnknown file: {filename}")
                continue

            info = DATAVERSE_FILES[filename]
            file_id = info["file_id"]
            expected_sha256 = str(info.get("sha256", ""))
            description = str(info.get("description", filename))

            print(f"\n{filename}")
            print("-" * len(filename))

            # Download
            url = f"{DATAVERSE_BASE_URL}/{file_id}"
            download_path = tmp_path / filename

            if not download_file(url, download_path, description):
                continue

            # Verify
            if verify and not verify_checksum(download_path, expected_sha256):
                continue

            # Extract
            if extract:
                if not extract_archive(download_path, PROJECT_ROOT):
                    continue

            success_count += 1

    print("\n" + "=" * 50)
    print(f"Downloaded {success_count}/{len(files_to_download)} files")

    return 0 if success_count == len(files_to_download) else 1


def download_from_local(archive_dir: Path, extract: bool = True) -> int:
    """Extract archives from a local directory (for offline use).

    Args:
        archive_dir: Directory containing the downloaded .tar.gz files
        extract: Whether to extract archives

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print(f"Extracting from local directory: {archive_dir}")
    print("=" * 50)

    success_count = 0
    archives = list(archive_dir.glob("*.tar.gz"))

    if not archives:
        print(f"No .tar.gz files found in {archive_dir}")
        return 1

    for archive_path in archives:
        print(f"\n{archive_path.name}")
        print("-" * len(archive_path.name))

        if extract:
            if extract_archive(archive_path, PROJECT_ROOT):
                success_count += 1
        else:
            success_count += 1

    print("\n" + "=" * 50)
    print(f"Processed {success_count}/{len(archives)} archives")

    return 0 if success_count == len(archives) else 1


def main() -> int:
    """Run the download script."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Download SBOM Toolkit dataset from Harvard Dataverse"
    )
    parser.add_argument(
        "--files",
        nargs="+",
        choices=list(DATAVERSE_FILES.keys()),
        help="Specific files to download (default: all)",
    )
    parser.add_argument(
        "--no-extract",
        action="store_true",
        help="Download only, don't extract archives",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip checksum verification",
    )
    parser.add_argument(
        "--local",
        type=Path,
        metavar="DIR",
        help="Extract from local directory instead of downloading",
    )

    args = parser.parse_args()

    if args.local:
        return download_from_local(args.local, extract=not args.no_extract)

    return download_from_dataverse(
        files=args.files,
        extract=not args.no_extract,
        verify=not args.no_verify,
    )


if __name__ == "__main__":
    sys.exit(main())

