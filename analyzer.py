import json
import os
import re
import sys
import csv


def train_classifier_from_real_data(path="dataset_20_labeled.csv"):
    X, y = [], []
    with open(path, newline="", encoding="latin-1") as f:
        reader = csv.DictReader(f)
        for row in reader:
            X.append([float(row[feat]) for feat in FEATURE_NAMES])
            y.append(row["label"])

    clf = DecisionTreeClassifier(max_depth=4, random_state=42)
    clf.fit(X, y)
    return clf


def load_manifest(ext_path):
    manifest_path = os.path.join(ext_path, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


def collect_js_source(ext_path):
    chunks = []
    for root, dirs, files in os.walk(ext_path):
        for name in files:
            if name.endswith((".js", ".html")):
                file_path = os.path.join(root, name)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        chunks.append(f.read())
                except OSError:
                    continue
    return "\n".join(chunks)


PERMISSION_INFO = {
    "tabs": "Lets the extension see the URLs, titles, and history of every open tab. Risky if it tracks browsing without needing to.",
    "activeTab": "Only gives access to the current tab, and only when the user clicks the extension icon. Much safer than 'tabs'.",
    "cookies": "Gives access to reading and modifying browser cookies, which can include login session tokens.",
    "history": "Lets the extension read and change your browsing history across all your signed-in devices.",
    "bookmarks": "Lets the extension read and change your saved bookmarks.",
    "downloads": "Lets the extension manage your downloads — see files, start or cancel downloads.",
    "geolocation": "Lets the extension access your physical location without the usual browser permission prompt.",
    "clipboardRead": "Lets the extension read whatever text or data you've copied — could capture passwords or sensitive text.",
    "debugger": "Gives near full control over a browser tab through Chrome's DevTools protocol, including reading data typed into pages. One of the highest-impact permissions available.",
    "webRequest": "Lets the extension observe network requests your browser makes.",
    "webRequestBlocking": "Lets the extension block or modify network requests before they are sent.",
    "management": "Lets the extension see and control your other installed extensions, apps and themes.",
    "privacy": "Lets the extension change your browser's privacy-related settings.",
    "nativeMessaging": "Lets the extension talk to a separate native program installed on your computer, outside the browser sandbox.",
    "proxy": "Lets the extension control how your browser connects to the internet.",
    "storage": "Lets the extension save data locally using the Chrome storage API. Low risk on its own.",
    "notifications": "Lets the extension show desktop notifications. Low risk.",
    "scripting": "Lets the extension inject and run JavaScript in web pages you visit.",
    "<all_urls>": "Grants access to every website you visit, not just specific ones. One of the broadest permissions possible.",
}

HIGH_RISK_PERMISSIONS = {
    "debugger", "webRequest", "webRequestBlocking", "tabs", "cookies",
    "history", "management", "proxy", "privacy", "<all_urls>",
    "nativeMessaging", "downloads",
}
PERMISSION_CATEGORIES = {
    "cookies": ["credential_theft", "financial_data"],
    "debugger": ["credential_theft", "system_control"],
    "clipboardRead": ["credential_theft", "financial_data"],
    "webRequest": ["financial_data", "network_interception", "browsing_tracking"],
    "webRequestBlocking": ["financial_data", "network_interception"],
    "proxy": ["financial_data", "network_interception"],
    "<all_urls>": ["browsing_tracking", "network_interception", "financial_data"],
    "geolocation": ["personal_identity"],
    "bookmarks": ["personal_identity", "browsing_tracking"],
    "history": ["browsing_tracking", "personal_identity"],
    "tabs": ["browsing_tracking"],
    "management": ["system_control"],
    "privacy": ["system_control", "personal_identity"],
    "nativeMessaging": ["credential_theft", "system_control"],
    "downloads": ["file_data"],
    "storage": [],
    "activeTab": [],
    "notifications": [],
    "scripting": ["system_control"],
}

CATEGORY_LABELS = {
    "credential_theft": "Credential / login theft",
    "financial_data": "Financial data exposure",
    "personal_identity": "Personal identity / location",
    "browsing_tracking": "Browsing behaviour tracking",
    "system_control": "System / device control",
    "network_interception": "Network interception",
    "file_data": "File / local data access",
}
SITE_CATEGORIES = {
    "financial": {
        "label": "Financial / banking",
        "domains": [
            "combank.lk", "hnb.lk", "boc.lk", "sampath.lk", "ndbbank.com",
            "seylan.lk", "peoplesbank.lk",
            "chase.com", "bankofamerica.com", "hsbc.com",
            "paypal.com", "stripe.com", "visa.com", "mastercard.com",
        ],
        "keywords": ["bank", "banking", "pay", "wallet", "finance", "credit"],
    },
    "social_email": {
        "label": "Social media / email",
        "domains": [
            "facebook.com", "instagram.com", "twitter.com", "x.com",
            "linkedin.com", "whatsapp.com", "gmail.com", "mail.google.com",
            "outlook.com", "yahoo.com",
        ],
        "keywords": ["mail", "social", "chat", "messenger"],
    },
    "government": {
        "label": "Government / public services",
        "domains": [
            "gov.lk", "ird.gov.lk", "epf.gov.lk", "immigration.gov.lk",
            "irs.gov", "gov.uk",
        ],
        "keywords": [".gov", "government", "immigration", "tax"],
    },
}


def _extract_domain(host_pattern):
    cleaned = host_pattern.lower()
    cleaned = re.sub(r'^[a-z*]+://', '', cleaned)
    cleaned = cleaned.split('/')[0]
    cleaned = re.sub(r'^(\*\.|www\.)', '', cleaned)
    return cleaned


def check_sensitive_sites(host_permissions):
    results = {cat: {"matched_known": [], "matched_keyword": []} for cat in SITE_CATEGORIES}
    targets_all = False

    for pattern in host_permissions:
        if pattern == "<all_urls>" or pattern.startswith("*://*/"):
            targets_all = True
            continue

        domain = _extract_domain(pattern)

        for cat, info in SITE_CATEGORIES.items():
            if any(domain == d or domain.endswith("." + d) for d in info["domains"]):
                results[cat]["matched_known"].append(pattern)
            elif any(kw in domain for kw in info["keywords"]):
                results[cat]["matched_keyword"].append(pattern)

    results["targets_all_sites"] = targets_all
    return results


def get_categories(permission):
    return PERMISSION_CATEGORIES.get(permission, [])


def categorize_permissions(declared_permissions):
    counts = {cat: 0 for cat in CATEGORY_LABELS}
    matched = {cat: [] for cat in CATEGORY_LABELS}

    for perm in declared_permissions:
        for cat in get_categories(perm):
            counts[cat] += 1
            matched[cat].append(perm)

    return counts, matched

def explain(permission):
    return PERMISSION_INFO.get(
        permission,
        "No specific description available for this permission — treat as unknown risk and review manually."
    )


CUSTOM_PATTERNS = {
    "geolocation": [r"navigator\.geolocation"],
    "clipboardRead": [r"navigator\.clipboard", r"execCommand\(\s*['\"]paste['\"]"],
    "activeTab": [],
    "storage": [r"chrome\.storage\."],
}

HOST_PERMISSION_PATTERN = re.compile(r"^(https?://|\*://|<all_urls>)")


def get_code_pattern(permission):
    if permission in CUSTOM_PATTERNS:
        return CUSTOM_PATTERNS[permission]
    safe = re.escape(permission)
    return [rf"chrome\.{safe}\."]


def analyze_permissions(manifest, source_code):
    declared = list(manifest.get("permissions", [])) + list(manifest.get("host_permissions", []))
    used = []
    unused = []
    high_risk_found = []

    for perm in declared:
        if perm in HIGH_RISK_PERMISSIONS or HOST_PERMISSION_PATTERN.match(perm):
            high_risk_found.append(perm)

        if HOST_PERMISSION_PATTERN.match(perm):
            used.append(perm)
            continue

        patterns = get_code_pattern(perm)
        if not patterns:
            used.append(perm)
            continue

        if any(re.search(p, source_code) for p in patterns):
            used.append(perm)
        else:
            unused.append(perm)

    return declared, used, unused, high_risk_found

FEATURE_NAMES = [
    "num_permissions", "num_unused", "num_high_risk", "unused_ratio",
    "credential_theft", "financial_data", "personal_identity",
    "browsing_tracking", "system_control", "network_interception",
    "file_data", "num_site_hits",
]


def build_features(declared, unused, high_risk_found, category_counts, site_results):
    num_declared = len(declared)
    num_unused = len(unused)
    num_high_risk = len(high_risk_found)
    unused_ratio = (num_unused / num_declared) if num_declared else 0.0

    num_site_hits = 0
    for cat in SITE_CATEGORIES:
        num_site_hits += len(site_results[cat]["matched_known"])
        num_site_hits += len(site_results[cat]["matched_keyword"])
    if site_results["targets_all_sites"]:
        num_site_hits += 1

    return [
        num_declared,
        num_unused,
        num_high_risk,
        unused_ratio,
        category_counts["credential_theft"],
        category_counts["financial_data"],
        category_counts["personal_identity"],
        category_counts["browsing_tracking"],
        category_counts["system_control"],
        category_counts["network_interception"],
        category_counts["file_data"],
        num_site_hits,
    ]

from sklearn.tree import DecisionTreeClassifier
import random


def build_training_data(seed=42, n_samples=200):
    rng = random.Random(seed)
    X = []
    y = []

    # anchor examples: all-zero risk = LOW, across a range of permission counts
    for num_declared in range(0, 16):
        for _ in range(4):
            X.append([num_declared, 0, 0, 0.0, 0, 0, 0, 0, 0, 0, 0, 0])
            y.append("LOW")

    for _ in range(n_samples):
        num_declared = rng.randint(1, 15)
        num_unused = rng.randint(0, num_declared)
        num_high_risk = rng.randint(0, num_declared)
        unused_ratio = num_unused / num_declared

        cred = rng.randint(0, num_declared)
        fin = rng.randint(0, num_declared)
        ident = rng.randint(0, num_declared)
        track = rng.randint(0, num_declared)
        sysc = rng.randint(0, num_declared)
        net = rng.randint(0, num_declared)
        filed = rng.randint(0, num_declared)
        site_hits = rng.randint(0, 3)

        score = (num_unused * 1.2 + num_high_risk * 1.8 + unused_ratio * 2.5
                 + cred * 2.0 + fin * 2.2 + track * 0.8 + sysc * 1.5
                 + net * 1.3 + site_hits * 2.0)

        if score <= 6:
            label = "LOW"
        elif score <= 14:
            label = "MEDIUM"
        else:
            label = "HIGH"

        X.append([num_declared, num_unused, num_high_risk, unused_ratio,
                   cred, fin, ident, track, sysc, net, filed, site_hits])
        y.append(label)

    return X, y


def train_classifier():
    X, y = build_training_data()
    clf = DecisionTreeClassifier(max_depth=5, random_state=42)
    clf.fit(X, y)
    return clf

if __name__ == "__main__":
    manifest = load_manifest("sample_extension_high_risk")
    code = collect_js_source("sample_extension_high_risk")

    declared, used, unused, high_risk_found = analyze_permissions(manifest, code)
    category_counts, category_matches = categorize_permissions(declared)

    host_perms = manifest.get("host_permissions", [])
    site_results = check_sensitive_sites(host_perms)

    print("Declared:", declared)
    print("Used:", used)
    print("Unused:", unused)
    print("High risk:", high_risk_found)
    print()
    for cat, label in CATEGORY_LABELS.items():
        if category_counts[cat] > 0:
            print(f"{label}: {category_counts[cat]} -> {category_matches[cat]}")
    print()
    print("Targets all sites:", site_results["targets_all_sites"])

    features = build_features(declared, unused, high_risk_found, category_counts, site_results)
    print()
    print("Feature vector:", features)
    print("As a labelled dict:", dict(zip(FEATURE_NAMES, features)))

    clf = train_classifier_from_real_data()
    prediction = clf.predict([features])[0]
    print()
    print("AI PREDICTED RISK LEVEL:", prediction)