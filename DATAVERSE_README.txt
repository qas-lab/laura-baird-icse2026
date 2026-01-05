SBOM Toolkit Dataset
====================

Software Bill of Materials Dataset for GNN-based Vulnerability Prediction


DESCRIPTION
-----------

This dataset supports research on applying graph neural networks to software
supply chain security. It contains Software Bills of Materials (SBOMs) from
open-source projects, enriched with vulnerability data, trained model
checkpoints, and evaluation results.

The accompanying code repository provides tools for:
- SBOM generation and vulnerability scanning
- Heterogeneous Graph Attention Network (HGAT) for vulnerability classification
- Multi-Layer Perceptron (MLP) for CVE attack chain prediction


DATASET CONTENTS
----------------

sboms.tar.gz (31 MB compressed, ~334 MB uncompressed)
    Software Bills of Materials in CycloneDX JSON format
    - data/filtered_sboms/: ~5,350 filtered SBOMs (commit hash identifiers)
    - data/scanned_sboms/: ~5,350 enriched SBOMs with vulnerability annotations

scans.tar.gz (7.4 MB compressed, ~95 MB uncompressed)
    Enriched vulnerability scan results
    - outputs/scans/: ~2,700 JSON scan files with CVSS scores and CWE mappings

models.tar.gz (752 KB compressed, ~1.8 MB uncompressed)
    Trained PyTorch model checkpoints
    - outputs/models/hgat_best.pt: HGAT node classifier
    - outputs/models/cascade_predictor.pt: CVE chain predictor
    - outputs/models/*_training_curves.png: Training visualizations

evaluations.tar.gz (2.7 MB compressed, ~37 MB uncompressed)
    Model evaluation results
    - outputs/evaluations/: Predictions, ground truth, and metrics

reference_data.tar.gz (2.9 MB compressed, ~9 MB uncompressed)
    Supporting reference data
    - data/external_chains/: Attack chain documentation
    - data/ac_data/: SCRM database (CSV/XLSX)
    - data/*_cache/: CVE, CWE, and CAPEC caches


DATA FORMATS
------------

SBOM Files (CycloneDX JSON)
    Standard CycloneDX 1.5 format containing:
    - components: Software packages with name, version, PURL
    - dependencies: Dependency relationships between components
    - vulnerabilities: Known CVEs affecting components
    - metadata: Generation tool information and timestamps

Scan Results (JSON)
    Enriched vulnerability records containing:
    - CVE identifiers and descriptions
    - CVSS scores (v2 and v3)
    - CWE weakness classifications
    - Severity ratings (CRITICAL, HIGH, MEDIUM, LOW)
    - Affected component references

Model Checkpoints (PyTorch .pt)
    Serialized model state including:
    - model_state_dict: Trained weights
    - input_dims: Feature dimensions for each node type
    - config: Hyperparameters used during training


USAGE
-----

1. Download all archive files to your local machine

2. Clone the code repository:
   git clone https://github.com/qas-lab/laura-baird-icse2026.git
   cd laura-baird-icse2026

3. Extract archives to the project root:
   for f in /path/to/downloads/*.tar.gz; do
       tar -xzf "$f" -C .
   done

4. Install dependencies:
   uv sync

5. Run inference with the trained models:
   uv run python -m sbom_toolkit.ml.hgat_predict \
       data/scanned_sboms/SAMPLE_enriched \
       --model outputs/models/hgat_best.pt

Alternatively, use the download script from the repository:
   uv run python scripts/download_data.py


FILE INTEGRITY
--------------

SHA256 checksums are provided in checksums.sha256. Verify with:
   sha256sum -c checksums.sha256


CITATION
--------

If you use this dataset in your research, please cite:

@misc{sbom_toolkit_dataset_2025,
  author = {Baird, Laura},
  title = {SBOM Toolkit: Software Bill of Materials Dataset for GNN-based Vulnerability Prediction},
  year = {2025},
  publisher = {Harvard Dataverse},
  doi = {10.7910/DVN/A6CZRB}
}


LICENSE
-------

This dataset is released under the MIT License.

The dataset includes derived data from the following sources:
- National Vulnerability Database (NVD): Public domain
- CWE (Common Weakness Enumeration): CC BY-SA 4.0
- CAPEC (Common Attack Pattern Enumeration): CC BY-SA 4.0
- Open-source project SBOMs: Various open-source licenses


CONTACT
-------

For questions about this dataset, please open an issue on the GitHub repository
or contact the author through Harvard Dataverse.


VERSION HISTORY
---------------

v1.0 (2025): Initial release

