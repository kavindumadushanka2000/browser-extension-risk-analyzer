import csv
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, classification_report
from analyzer import FEATURE_NAMES

MIN_ROWS_FOR_SPLIT = 15


def load_dataset(path="dataset.csv"):
    X, y, names = [], [], []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            X.append([float(row[feat]) for feat in FEATURE_NAMES])
            y.append(row["label"])
            names.append(row["name"])
    return X, y, names


def run_cross_validation(X, y, n_splits=5):
    print(f"\n--- {n_splits}-Fold Cross-Validation ---")
    clf = DecisionTreeClassifier(max_depth=4, random_state=42)

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scores = cross_val_score(clf, X, y, cv=skf, scoring="accuracy")

    for i, score in enumerate(scores, 1):
        print(f"  Fold {i}: {score:.2%}")

    print(f"\n  Mean accuracy: {scores.mean():.2%}")
    print(f"  Std deviation: {scores.std():.2%}")
    print(f"  (This means results vary by about ±{scores.std():.1%} depending on which")
    print(f"   extensions land in the test set — this is the honest range to report,")
    print(f"   not a single lucky/unlucky split.)")


def main():
    X, y, names = load_dataset("dataset_20_labeled.csv")
    print(f"Loaded {len(X)} labelled extensions from dataset.csv")
    print(f"Label counts: LOW={y.count('LOW')}  MEDIUM={y.count('MEDIUM')}  HIGH={y.count('HIGH')}\n")

    run_cross_validation(X, y)

    if len(X) < MIN_ROWS_FOR_SPLIT:
        print(f"\nOnly {len(X)} rows — too few for a real train/test split.")
        print("Training on ALL rows, reporting TRAINING accuracy only.\n")
        clf = DecisionTreeClassifier(max_depth=4, random_state=42)
        clf.fit(X, y)
        preds = clf.predict(X)
        print("Training accuracy:", accuracy_score(y, preds))
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )
        clf = DecisionTreeClassifier(max_depth=4, random_state=42)
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        print(f"\nHeld-out test accuracy: {accuracy_score(y_test, preds):.2%}\n")
        print(classification_report(y_test, preds, zero_division=0))

    print("\n--- Decision tree structure ---")
    print(export_text(clf, feature_names=FEATURE_NAMES))


if __name__ == "__main__":
    main()