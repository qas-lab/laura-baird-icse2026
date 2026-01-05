"""
End-to-end demonstration of cascade vulnerability prediction.

This script demonstrates the complete workflow:
1. Load attack chain data
2. Train cascade predictor
3. (Optionally) Generate SBOMs from incident repositories
4. Predict cascades in real SBOMs
5. Evaluate performance

Usage:
    python -m sbom_toolkit.ml.demo_cascade_prediction --quick
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]
    NUMPY_AVAILABLE = False

from .cascade_data_loader import CascadeDataLoader
from .cascade_predictor import CascadePredictor, CascadeTrainer


def quick_demo() -> int:
    """Run a quick demonstration with minimal setup."""
    if not NUMPY_AVAILABLE:
        print("Error: NumPy required. Install: pip install numpy torch")
        return 1

    print("=" * 80)
    print("CASCADED VULNERABILITY PREDICTION - QUICK DEMO")
    print("=" * 80)
    print()

    # Step 1: Load data
    print("STEP 1: Loading Attack Chain Data")
    print("-" * 40)

    loader = CascadeDataLoader(
        external_chains_path=Path("data/external_chains"),
        incidents_path=Path("supply-chain-seeds/incidents.json"),
        cve_cache_dir=Path("data/cve_cache"),
    )

    stats = loader.load_all()
    print(f"  External chains: {stats['num_external_chains']}")
    print(f"  Incident reports: {stats['num_incidents']}")
    print(f"  Unique CVEs: {stats['num_unique_cves']}")
    print(
        f"  Training pairs: {stats['total_training_pairs']} "
        f"({stats['num_positive_pairs']} positive, {stats['num_negative_pairs']} negative)"
    )
    print()

    if stats["total_training_pairs"] < 10:
        print("✗ Insufficient training data. Need at least 10 pairs.")
        print("  Ensure data/external_chains and supply-chain-seeds/incidents.json exist.")
        return 1

    # Show example chain
    if loader.chains:
        chain = loader.chains[0]
        print(f"  Example chain: {chain.title}")
        print(f"    CVEs: {', '.join(chain.cve_ids)}")
        print(f"    Source: {chain.source}")
        print()

    # Step 2: Prepare data
    print("STEP 2: Preparing Training Data")
    print("-" * 40)

    pairs, labels = loader.generate_training_pairs(negative_ratio=2.0)
    X, y = [], []

    for (cve1, cve2), label in zip[tuple[tuple[str, str], int]](pairs, labels):
        try:
            feat = loader.get_pair_features(cve1, cve2)
            X.append(feat)
            y.append(label)
        except Exception as e:
            print(f"Warning: Could not get pair features: {e}")
            continue

    X = np.stack(X)
    y = np.array(y, dtype=np.int64)

    # Split: 70% train, 20% val, 10% test
    rng = np.random.RandomState(42)
    indices = rng.permutation(len(X))
    X = X[indices]
    y = y[indices]

    n = len(X)
    n_train = int(0.7 * n)
    n_val = int(0.2 * n)

    X_train, y_train = X[:n_train], y[:n_train]
    X_val, y_val = X[n_train : n_train + n_val], y[n_train : n_train + n_val]
    X_test, y_test = X[n_train + n_val :], y[n_train + n_val :]

    print(f"  Train: {len(X_train)} samples ({y_train.sum()} positive)")
    print(f"  Val:   {len(X_val)} samples ({y_val.sum()} positive)")
    print(f"  Test:  {len(X_test)} samples ({y_test.sum()} positive)")
    print()

    # Step 3: Train model
    print("STEP 3: Training Cascade Predictor")
    print("-" * 40)

    model = CascadePredictor(input_dim=22, hidden_dims=(64, 32, 16), dropout=0.3)
    trainer = CascadeTrainer(model, learning_rate=0.001, device="cpu")

    print(f"  Architecture: {[64, 32, 16]} hidden dims")
    print(f"  Parameters: {sum(p.numel() for p in model.parameters())}")
    print("  Training for 50 epochs (with early stopping)...")
    print()

    _ = trainer.train(
        X_train,
        y_train,
        X_val,
        y_val,
        epochs=50,
        batch_size=16,
        early_stopping_patience=10,
        verbose=True,
    )

    # Step 4: Evaluate
    print()
    print("STEP 4: Evaluation on Test Set")
    print("-" * 40)

    test_loss, test_auc = trainer.evaluate(X_test, y_test)
    print(f"  Test Loss: {test_loss:.4f}")
    print(f"  Test AUC-ROC: {test_auc:.4f}")
    print()

    # Interpretation
    print("STEP 5: Interpretation")
    print("-" * 40)

    if test_auc > 0.75:
        print("  Strong Performance (AUC > 0.75)")
        print("  The model can reliably distinguish CVE pairs that are likely")
        print("  to be chained together from random pairs.")
        feasibility = "HIGH"
    elif test_auc > 0.65:
        print("  Moderate Performance (AUC 0.65-0.75)")
        print("  The model shows predictive capability but may need improvement.")
        print("  Consider: more data, feature engineering, or architecture changes.")
        feasibility = "MODERATE"
    else:
        print("  Weak Performance (AUC < 0.65)")
        print("  The model struggles to predict cascades. This suggests:")
        print("    - Insufficient training data (need more documented chains)")
        print("    - Features may not capture cascade patterns")
        print("    - Task may require domain-specific signals (CWE embeddings, etc.)")
        feasibility = "LOW"

    print()
    print("=" * 80)
    print(f"FEASIBILITY ASSESSMENT: {feasibility}")
    print("=" * 80)
    print()

    # Save model
    output_dir = Path("outputs/models")
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "cascade_predictor_demo.pt"
    trainer.save(model_path)
    print(f"Model saved to: {model_path}")

    # Example prediction
    print()
    print("EXAMPLE: Predicting CVE pair")
    print("-" * 40)

    if len(loader.chains) > 0:
        chain = loader.chains[0]
        if len(chain.cve_ids) >= 2:
            cve1, cve2 = chain.cve_ids[0], chain.cve_ids[1]
            try:
                feat = loader.get_pair_features(cve1, cve2)
                import torch

                feat_t = torch.from_numpy(feat).float().unsqueeze(0)
                prob = model.predict_proba(feat_t).item()
                print(f"  Pair: {cve1} -> {cve2}")
                print("  Ground truth: POSITIVE (from attack chain)")
                print(f"  Model prediction: {prob:.4f}")
                if prob > 0.5:
                    print("  Model correctly predicts this as a likely cascade")
                else:
                    print("  Model incorrectly predicts this as unlikely")
            except Exception as e:
                print(f"  Could not demonstrate prediction: {e}")

    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main demo function."""
    parser = argparse.ArgumentParser(description="Demonstrate cascade vulnerability prediction")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick demo with default settings",
    )

    args = parser.parse_args(argv)

    if args.quick:
        return quick_demo()
    else:
        # Could add more comprehensive demos here
        print("Use --quick for a quick demonstration")
        return 0


if __name__ == "__main__":
    sys.exit(main())
