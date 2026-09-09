import csv

FEATURE_NAMES = [
    "num_permissions", "num_unused", "num_high_risk", "unused_ratio",
    "credential_theft", "financial_data", "personal_identity",
    "browsing_tracking", "system_control", "network_interception",
    "file_data", "num_site_hits",
]

CATEGORY_LABELS = {
    "credential_theft": "Credential / login theft",
    "financial_data": "Financial data exposure",
    "personal_identity": "Personal identity / location",
    "browsing_tracking": "Browsing behaviour tracking",
    "system_control": "System / device control",
    "network_interception": "Network interception",
    "file_data": "File / local data access",
}


def main():
    rows = list(csv.DictReader(open("dataset.csv", encoding="utf-8")))
    total = len(rows)
    print(f"Total real extensions analyzed: {total}\n")

    # Over-privilege prevalence
    has_unused = sum(1 for r in rows if int(r["num_unused"]) > 0)
    high_unused_ratio = sum(1 for r in rows if float(r["unused_ratio"]) >= 0.3)
    has_high_risk = sum(1 for r in rows if int(r["num_high_risk"]) > 0)
    targets_all = sum(1 for r in rows if float(r["num_site_hits"]) > 0)

    print("=== OVER-PRIVILEGE PREVALENCE ===")
    print(f"Extensions with at least 1 unused permission: {has_unused} ({has_unused/total:.1%})")
    print(f"Extensions with unused_ratio >= 30%: {high_unused_ratio} ({high_unused_ratio/total:.1%})")
    print(f"Extensions with at least 1 high-risk permission: {has_high_risk} ({has_high_risk/total:.1%})")
    print(f"Extensions with broad/sensitive site access: {targets_all} ({targets_all/total:.1%})")

    print("\n=== THREAT CATEGORY PREVALENCE ===")
    for cat, label in CATEGORY_LABELS.items():
        count = sum(1 for r in rows if float(r[cat]) > 0)
        print(f"{label}: {count} ({count/total:.1%})")

    # Averages
    avg_unused_ratio = sum(float(r["unused_ratio"]) for r in rows) / total
    avg_permissions = sum(int(r["num_permissions"]) for r in rows) / total
    print(f"\n=== AVERAGES ===")
    print(f"Average permissions declared per extension: {avg_permissions:.1f}")
    print(f"Average unused ratio: {avg_unused_ratio:.1%}")

    # Top 10 most over-privileged (by unused_ratio, among those with 3+ permissions to avoid tiny-extension noise)
    filtered = [r for r in rows if int(r["num_permissions"]) >= 3]
    top10 = sorted(filtered, key=lambda r: float(r["unused_ratio"]), reverse=True)[:10]
    print(f"\n=== TOP 10 MOST OVER-PRIVILEGED (by unused ratio, 3+ permissions) ===")
    for r in top10:
        print(f"  {r['name']}: {r['num_unused']}/{r['num_permissions']} unused ({float(r['unused_ratio']):.0%})")


if __name__ == "__main__":
    main()