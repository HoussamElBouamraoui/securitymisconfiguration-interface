#!/usr/bin/env python3
"""
Test de scan sur cibles AUTORISÉES uniquement (OWASP A05:2025).
Utilise --test-authorized pour n'accepter que les URLs dans AUTHORIZED_TEST_TARGETS
ou la variable d'environnement INJECTION_ALLOWED_TARGETS.

Exemples (depuis la racine du repo ou depuis injection/) :
  python -m injection.tests.run_authorized_scan
  python -m injection.tests.run_authorized_scan --url "http://testphp.vulnweb.com/listproducts.php?cat=1"
  set INJECTION_ALLOWED_TARGETS=http://localhost:8080
  python -m injection.tests.run_authorized_scan --url "http://localhost:8080/app?id=1"
"""

from __future__ import annotations

import argparse
import os
import sys

# S'assurer que le package injection est importable
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Cibles autorisées par défaut (sites de test publics connus)
DEFAULT_ALLOWED = [
    "http://testphp.vulnweb.com",
    "https://testphp.vulnweb.com",
    "http://dvwa",
    "http://localhost",
    "http://127.0.0.1",
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Lancer InjectionHunter sur une cible autorisée uniquement")
    ap.add_argument("--url", default=None, help="URL cible (sinon utilise INJECTION_TARGET ou testphp)")
    ap.add_argument("--modules", default="sqli,xss,forms", help="Modules à exécuter (défaut: sqli,xss,forms)")
    ap.add_argument("--aggressive", action="store_true", help="Mode agressif")
    ap.add_argument("--stealth", action="store_true", default=True, help="Mode furtif (défaut: True)")
    args = ap.parse_args()

    url = args.url or os.environ.get("INJECTION_TARGET", "http://testphp.vulnweb.com/listproducts.php?cat=1")
    allowed = os.environ.get("INJECTION_ALLOWED_TARGETS", "")
    allowed_list = [u.strip() for u in allowed.split(",") if u.strip()] if allowed else DEFAULT_ALLOWED

    base = url.split("?")[0].rstrip("/")
    if not any(base.startswith(a) or a in base for a in allowed_list):
        print(f"[ERREUR] URL non autorisée: {url}")
        print(f"Cibles autorisées: {allowed_list}")
        return 2

    os.chdir(_ROOT)
    sys.argv = [
        "hunter.py",
        "-u", url,
        "-m", args.modules,
        "--test-authorized",
    ]
    if args.aggressive:
        sys.argv.append("--aggressive")
    if args.stealth:
        sys.argv.append("--stealth")

    # Forcer la liste autorisée pour --test-authorized
    os.environ["INJECTION_ALLOWED_TARGETS"] = ",".join(allowed_list)

    try:
        from hunter import main as hunter_main
        hunter_main()
        return 0
    except SystemExit as e:
        return e.code if e.code is not None else 0
    except Exception as e:
        print(f"[ERREUR] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
