#!/usr/bin/env python3
"""
Test COMPLET sur http://testphp.vulnweb.com/ (site Acunetix volontairement vulnerable).
Lance plusieurs URLs + tous les modules d'injection, fusionne les resultats, exporte JSON.
Usage (depuis injection/ ou racine du repo):
  python -m injection.tests.run_full_test_testphp
  python -m injection.tests.run_full_test_testphp --out report.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Racine du package injection
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

BASE = "http://testphp.vulnweb.com"
# URLs avec parametres pour maximiser la couverture (SQLi, XSS, etc.)
TEST_URLS = [
    f"{BASE}/listproducts.php?cat=1",
    f"{BASE}/search.php?searchFor=test",
    f"{BASE}/artist.php?artist=1",
    f"{BASE}/listproducts.php?cat=2",
    f"{BASE}/product.php?pic=1",
]
MODULES = "sqli,xss,cmdi,lfi,forms,admin,cookies"


def _dedupe_vulns(vulns: list) -> list:
    seen = set()
    out = []
    for v in vulns:
        key = (v.get("type"), v.get("param") or v.get("path") or "", v.get("url", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Test complet testphp.vulnweb.com")
    ap.add_argument("--out", default="testphp_full_report.json", help="Fichier JSON de sortie")
    ap.add_argument("--modules", default=MODULES, help="Modules a lancer")
    args = ap.parse_args()

    os.chdir(_ROOT)
    all_vulns = []
    for i, url in enumerate(TEST_URLS):
        print(f"\n{'='*60}\n[URL {i+1}/{len(TEST_URLS)}] {url}\n{'='*60}")
        tmp_json = _ROOT / f"._tmp_scan_{i}.json"
        cmd = [
            sys.executable, "hunter.py",
            "-u", url,
            "-m", args.modules,
            "--stealth",
            "--test-authorized",
            "--out-json", str(tmp_json),
        ]
        try:
            result = subprocess.run(cmd, cwd=_ROOT, timeout=180)
            if result.returncode != 0:
                print(f"[WARN] hunter exit code {result.returncode} for {url}")
        except subprocess.TimeoutExpired:
            print(f"[WARN] timeout for {url}")
        except Exception as e:
            print(f"[WARN] {e}")
        if tmp_json.exists():
            try:
                data = json.loads(tmp_json.read_text(encoding="utf-8"))
                for v in data.get("vulnerabilities", []):
                    v["_scanned_url"] = url
                all_vulns.extend(data.get("vulnerabilities", []))
            except Exception:
                pass
            tmp_json.unlink(missing_ok=True)

    merged = _dedupe_vulns(all_vulns)
    report = {"target": BASE, "urls_tested": TEST_URLS, "vulnerabilities": merged}
    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[OK] Rapport fusionne: {len(merged)} vulnerabilite(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
