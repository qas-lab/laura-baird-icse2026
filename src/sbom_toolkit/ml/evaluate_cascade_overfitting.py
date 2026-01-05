"""
Comprehensive evaluation of cascade predictor for overfitting detection.

This script performs multiple analyses to detect potential overfitting:
1. Train/Val/Test AUC comparison
2. Learning curves analysis
3. Prediction distribution analysis
4. Cross-validation evaluation
5. Feature importance/sensitivity analysis
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

try:
    import numpy as np
    import torch

    NUMPY_AVAILABLE = True
    TORCH_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]
    torch = None  # type: ignore[assignment]
    NUMPY_AVAILABLE = False
    TORCH_AVAILABLE = False

try:
    from sklearn.metrics import (
        accuracy_score,
        roc_auc_score,
    )
    from sklearn.model_selection import KFold

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from .cascade_data_loader import CascadeDataLoader
from .cascade_predictor import CascadePredictor, CascadeTrainer


def prepare_data(
    loader: CascadeDataLoader,
    val_split: float = 0.2,
    test_split: float = 0.1,
    seed: int = 42,
) -> tuple[
    tuple[np.ndarray, np.ndarray],
    tuple[np.ndarray, np.ndarray],
    tuple[np.ndarray, np.ndarray],
]:
    """Prepare train/val/test splits with consistent seeding."""
    if not NUMPY_AVAILABLE:
        raise ImportError("NumPy required")

    pairs, labels = loader.generate_training_pairs(negative_ratio=2.0)

    # Extract features
    X_rows: list[np.ndarray] = []
    y_labels: list[int] = []
    for (cve1, cve2), label in zip(pairs, labels, strict=True):
        try:
            feat = loader.get_pair_features(cve1, cve2)
            X_rows.append(feat)
            y_labels.append(label)
        except Exception:
            continue

    X = np.stack(X_rows)
    y = np.array(y_labels, dtype=np.int64)

    # Shuffle and split with fixed seed for reproducibility
    rng = np.random.RandomState(seed)
    indices = rng.permutation(len(X))
    X = X[indices]
    y = y[indices]

    n = len(X)
    n_test = int(n * test_split)
    n_val = int(n * val_split)
    n_train = n - n_test - n_val

    X_train, y_train = X[:n_train], y[:n_train]
    X_val, y_val = X[n_train : n_train + n_val], y[n_train : n_train + n_val]
    X_test, y_test = X[n_train + n_val :], y[n_train + n_val :]

    return (X_train, y_train), (X_val, y_val), (X_test, y_test)


def evaluate_dataset_splits(
    model_path: Path, loader: CascadeDataLoader, device: str = "cpu"
) -> dict[str, Any]:
    """Evaluate model on train/val/test splits."""
    print("\n" + "=" * 80)
    print("OVERFITTING CHECK #1: Train/Val/Test Performance Comparison")
    print("=" * 80)

    (X_train, y_train), (X_val, y_val), (X_test, y_test) = prepare_data(loader)

    # Load model
    checkpoint = torch.load(model_path, map_location=device)
    model = CascadePredictor(input_dim=22, hidden_dims=(64, 32, 16), dropout=0.3)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    model = model.to(device)

    def evaluate_split(X: np.ndarray, y: np.ndarray, split_name: str) -> dict[str, float]:
        """Evaluate on a single split."""
        X_t = torch.from_numpy(X).float().to(device)
        with torch.no_grad():
            logits = model(X_t)
            probs = torch.sigmoid(logits).cpu().numpy()
            preds = (probs >= 0.5).astype(int)

        auc = float(roc_auc_score(y, probs))
        acc = float(accuracy_score(y, preds))

        print(f"\n{split_name} Split:")
        print(f"  Samples: {len(y)} ({y.sum()} positive)")
        print(f"  AUC-ROC: {auc:.4f}")
        print(f"  Accuracy: {acc:.4f}")

        return {"auc": auc, "accuracy": acc, "n_samples": len(y), "n_positive": int(y.sum())}

    train_metrics = evaluate_split(X_train, y_train, "Training")
    val_metrics = evaluate_split(X_val, y_val, "Validation")
    test_metrics = evaluate_split(X_test, y_test, "Test")

    # Overfitting indicators
    train_val_gap = train_metrics["auc"] - val_metrics["auc"]
    train_test_gap = train_metrics["auc"] - test_metrics["auc"]

    print("\n" + "-" * 80)
    print("Overfitting Indicators:")
    print(f"  Train-Val AUC Gap: {train_val_gap:.4f}")
    print(f"  Train-Test AUC Gap: {train_test_gap:.4f}")

    if train_val_gap > 0.15:
        print("  ⚠️  WARNING: Large train-val gap suggests potential overfitting!")
    elif train_val_gap > 0.10:
        print("  ⚠️  CAUTION: Moderate train-val gap detected")
    else:
        print("  ✓ Train-val gap is acceptable")

    return {
        "train": train_metrics,
        "val": val_metrics,
        "test": test_metrics,
        "train_val_gap": train_val_gap,
        "train_test_gap": train_test_gap,
    }


def cross_validation_evaluation(
    loader: CascadeDataLoader, n_folds: int = 5, device: str = "cpu"
) -> dict[str, Any]:
    """Perform k-fold cross-validation to assess generalization."""
    print("\n" + "=" * 80)
    print(f"OVERFITTING CHECK #2: {n_folds}-Fold Cross-Validation")
    print("=" * 80)

    pairs, labels = loader.generate_training_pairs(negative_ratio=2.0)

    # Extract features
    X_rows: list[np.ndarray] = []
    y_labels: list[int] = []
    for (cve1, cve2), label in zip(pairs, labels, strict=True):
        try:
            feat = loader.get_pair_features(cve1, cve2)
            X_rows.append(feat)
            y_labels.append(label)
        except Exception:
            continue

    X = np.stack(X_rows)
    y = np.array(y_labels, dtype=np.int64)

    kf = KFold(n_splits=n_folds, shuffle=True, random_state=42)
    fold_aucs = []

    for fold_idx, (train_idx, val_idx) in enumerate(kf.split(X), start=1):
        X_train_fold, y_train_fold = X[train_idx], y[train_idx]
        X_val_fold, y_val_fold = X[val_idx], y[val_idx]

        # Train small model for this fold
        model = CascadePredictor(input_dim=22, hidden_dims=(64, 32, 16), dropout=0.3)
        trainer = CascadeTrainer(model, learning_rate=0.001, device=device)

        _ = trainer.train(
            X_train_fold,
            y_train_fold,
            X_val_fold,
            y_val_fold,
            epochs=50,
            batch_size=16,
            early_stopping_patience=10,
            verbose=False,
        )

        _, val_auc = trainer.evaluate(X_val_fold, y_val_fold)
        fold_aucs.append(val_auc)
        print(f"  Fold {fold_idx}: Validation AUC = {val_auc:.4f}")

    mean_auc = float(np.mean(fold_aucs))
    std_auc = float(np.std(fold_aucs))

    print("\nCross-Validation Results:")
    print(f"  Mean AUC: {mean_auc:.4f} ± {std_auc:.4f}")

    if std_auc > 0.10:
        print("  ⚠️  WARNING: High variance across folds suggests unstable model!")
    elif std_auc > 0.05:
        print("  ⚠️  CAUTION: Moderate variance detected")
    else:
        print("  ✓ Low variance - model is stable")

    return {"fold_aucs": fold_aucs, "mean_auc": mean_auc, "std_auc": std_auc}


def analyze_prediction_distribution(
    model_path: Path, loader: CascadeDataLoader, device: str = "cpu"
) -> dict[str, Any]:
    """Analyze prediction distributions for signs of overconfidence."""
    print("\n" + "=" * 80)
    print("OVERFITTING CHECK #3: Prediction Distribution Analysis")
    print("=" * 80)

    (X_train, y_train), (X_val, y_val), (X_test, y_test) = prepare_data(loader)

    # Load model
    checkpoint = torch.load(model_path, map_location=device)
    model = CascadePredictor(input_dim=22, hidden_dims=(64, 32, 16), dropout=0.3)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    model = model.to(device)

    def get_predictions(X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        X_t = torch.from_numpy(X).float().to(device)
        with torch.no_grad():
            logits = model(X_t)
            probs = torch.sigmoid(logits).cpu().numpy()
        return probs, y

    test_probs, test_labels = get_predictions(X_test, y_test)

    # Calculate calibration metrics
    positive_probs = test_probs[test_labels == 1]
    negative_probs = test_probs[test_labels == 0]

    print("\nTest Set Prediction Statistics:")
    print(f"  Positive pairs: mean={positive_probs.mean():.4f}, std={positive_probs.std():.4f}")
    print(f"  Negative pairs: mean={negative_probs.mean():.4f}, std={negative_probs.std():.4f}")

    # Check for overconfidence
    extreme_preds = np.sum((test_probs > 0.95) | (test_probs < 0.05))
    extreme_ratio = extreme_preds / len(test_probs)

    print(
        f"\n  Extreme predictions (>0.95 or <0.05): {extreme_preds}/{len(test_probs)} ({extreme_ratio:.2%})"
    )

    if extreme_ratio > 0.5:
        print("  ⚠️  WARNING: High proportion of extreme predictions suggests overconfidence!")
    elif extreme_ratio > 0.3:
        print("  ⚠️  CAUTION: Moderate overconfidence detected")
    else:
        print("  ✓ Prediction distribution looks reasonable")

    return {
        "positive_mean": float(positive_probs.mean()),
        "positive_std": float(positive_probs.std()),
        "negative_mean": float(negative_probs.mean()),
        "negative_std": float(negative_probs.std()),
        "extreme_ratio": float(extreme_ratio),
    }


def main(argv: list[str] | None = None) -> int:
    """Main evaluation function."""
    parser = argparse.ArgumentParser(
        description="Comprehensive overfitting evaluation for cascade predictor"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="outputs/models/cascade_predictor_reeval.pt",
        help="Path to trained model",
    )
    parser.add_argument(
        "--external-chains", type=str, default="data/external_chains", help="External chains path"
    )
    parser.add_argument(
        "--incidents",
        type=str,
        default="supply-chain-seeds/incidents.json",
        help="Incidents JSON path",
    )
    parser.add_argument(
        "--cve-cache", type=str, default="data/cve_cache", help="CVE cache directory"
    )
    parser.add_argument("--cpu", action="store_true", help="Force CPU")
    parser.add_argument("--skip-cv", action="store_true", help="Skip cross-validation (slow)")

    args = parser.parse_args(argv)

    if not TORCH_AVAILABLE or not NUMPY_AVAILABLE or not SKLEARN_AVAILABLE:
        print("Error: Required packages not available")
        return 1

    device = "cpu" if args.cpu else ("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # Load data
    loader = CascadeDataLoader(
        external_chains_path=Path(args.external_chains),
        incidents_path=Path(args.incidents),
        cve_cache_dir=Path(args.cve_cache),
    )
    stats = loader.load_all()
    print(
        f"\nDataset: {stats['total_training_pairs']} pairs "
        f"({stats['num_positive_pairs']} positive, {stats['num_negative_pairs']} negative)"
    )

    model_path = Path(args.model)
    if not model_path.exists():
        print(f"Error: Model not found at {model_path}")
        return 1

    # Run evaluations
    results = {}

    # Check 1: Train/Val/Test splits
    results["split_eval"] = evaluate_dataset_splits(model_path, loader, device)

    # Check 2: Cross-validation (optional, slow)
    if not args.skip_cv:
        results["cv_eval"] = cross_validation_evaluation(loader, n_folds=5, device=device)
    else:
        print("\n[Skipping cross-validation - use without --skip-cv to enable]")

    # Check 3: Prediction distribution
    results["dist_eval"] = analyze_prediction_distribution(model_path, loader, device)

    # Final summary
    print("\n" + "=" * 80)
    print("FINAL OVERFITTING ASSESSMENT")
    print("=" * 80)

    flags = []
    if results["split_eval"]["train_val_gap"] > 0.15:
        flags.append("⚠️  Large train-val performance gap")
    if "cv_eval" in results and results["cv_eval"]["std_auc"] > 0.10:
        flags.append("⚠️  High variance in cross-validation")
    if results["dist_eval"]["extreme_ratio"] > 0.5:
        flags.append("⚠️  Overconfident predictions")

    if flags:
        print("\nPotential Issues Detected:")
        for flag in flags:
            print(f"  {flag}")
        print("\nThe model shows signs of overfitting. Consider:")
        print("  - Increase dropout rate")
        print("  - Add L2 regularization")
        print("  - Reduce model capacity")
        print("  - Collect more training data")
    else:
        print("\n✓ No major overfitting concerns detected")
        print(f"  Test AUC: {results['split_eval']['test']['auc']:.4f} is a reliable estimate")

    return 0


if __name__ == "__main__":
    sys.exit(main())
