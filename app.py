import os
import shutil
import tempfile

from flask import Flask, render_template, request

from analyzer import (
    load_manifest, collect_js_source, analyze_permissions,
    categorize_permissions, check_sensitive_sites, build_features,
    train_classifier_from_real_data, CATEGORY_LABELS, SITE_CATEGORIES,
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

        result = {
            "name": manifest.get("name", "Unknown extension"),
            "version": manifest.get("version", "?"),
            "declared": declared,
            "used": used,
            "unused": unused,
            "category_counts": category_counts,
            "category_matches": category_matches,
            "category_labels": CATEGORY_LABELS,
            "site_results": site_results,
            "site_categories": SITE_CATEGORIES,
            "prediction": prediction,
        }
        return render_template("result.html", r=result)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    app.run(debug=True, port=5000)