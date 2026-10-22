import json, sys
report = json.load(open("reports/bandit_report.json"))
blocking = [r for r in report["results"]
            if r["issue_severity"] in ("MEDIUM", "HIGH")
            or r["test_id"] in ("B105", "B106", "B107")]   # hardcoded credentials
for r in blocking:
    print(f'{r["test_id"]} {r["issue_severity"]:6} {r["filename"]}:{r["line_number"]} {r["issue_text"]}')
if blocking:
    print(f"GATE FAILED: {len(blocking)} blocking finding(s). Release blocked.")
    sys.exit(1)
print("GATE PASSED: no blocking findings.") 