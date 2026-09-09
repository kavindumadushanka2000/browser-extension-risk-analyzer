import os
import shutil
import tempfile

from flask import Flask, render_template, request

from analyzer import (
    load_manifest, collect_js_source, analyze_permissions,
    categorize_permissions, check_sensitive_sites, build_features,
    train_classifier_from_real_data, CATEGORY_LABELS, SITE_CATEGORIES, explain,
)

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    files = request.files.getlist("folder")

    if not files or files[0].filename == "":
        return render_template("index.html", error="No folder selected.")

    tmp_dir = tempfile.mkdtemp(prefix="ext_upload_")
    try:
        for f in files:
            rel_path = f.filename
            dest_path = os.path.join(tmp_dir, rel_path)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            f.save(dest_path)

        entries = os.listdir(tmp_dir)
        if len(entries) == 1 and os.path.isdir(os.path.join(tmp_dir, entries[0])):
            ext_path = os.path.join(tmp_dir, entries[0])
        else:
            ext_path = tmp_dir

        try:
            manifest = load_manifest(ext_path)
        except FileNotFoundError:
            return render_template("index.html", error="No manifest.json found. Select the extension's root folder.")

        code = collect_js_source(ext_path)
        declared, used, unused, high_risk_found = analyze_permissions(manifest, code)
        category_counts, category_matches = categorize_permissions(declared)
        host_perms = manifest.get("host_permissions", [])
        site_results = check_sensitive_sites(host_perms)

        clf = train_classifier_from_real_data()
        features = build_features(declared, unused, high_risk_found, category_counts, site_results)
        prediction = clf.predict([features])[0]

        # Get real confidence percentages for each risk level from the trained model
        proba = clf.predict_proba([features])[0]
        proba_dict = dict(zip(clf.classes_, proba))
        risk_confidence = {
            "LOW": round(proba_dict.get("LOW", 0) * 100),
            "MEDIUM": round(proba_dict.get("MEDIUM", 0) * 100),
            "HIGH": round(proba_dict.get("HIGH", 0) * 100),
        }

        # Build percentage bars for threat categories (relative to declared permissions)
        num_declared = len(declared) if declared else 1
        category_percentages = {
            cat: round((category_counts[cat] / num_declared) * 100)
            for cat in category_counts
        }

        # Build percentage for sensitive site categories
        site_percentages = {}
        for cat, info in SITE_CATEGORIES.items():
            hits = len(site_results[cat]["matched_known"]) + len(site_results[cat]["matched_keyword"])
            site_percentages[cat] = min(100, hits * 50) if hits > 0 else 0
        if site_results["targets_all_sites"]:
            for cat in site_percentages:
                site_percentages[cat] = max(site_percentages[cat], 60)

        # Privilege usage bar (used vs unused)
        used_pct = round((len(used) / num_declared) * 100) if declared else 0
        unused_pct = 100 - used_pct

        result = {
            "name": manifest.get("name", "Unknown extension"),
            "version": manifest.get("version", "?"),
            "declared": declared,
            "used": used,
            "unused": unused,
            "unused_explained": [(p, explain(p)) for p in unused],
            "category_counts": category_counts,
            "category_matches": category_matches,
            "category_labels": CATEGORY_LABELS,
            "category_percentages": category_percentages,
            "site_results": site_results,
            "site_categories": SITE_CATEGORIES,
            "site_percentages": site_percentages,
            "prediction": prediction,
            "risk_confidence": risk_confidence,
            "used_pct": used_pct,
            "unused_pct": unused_pct,
        }
        return render_template("result.html", r=result)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    app.run(debug=True, port=5000)