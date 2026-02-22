#!/usr/bin/env python3
"""Script de test pour diagnostiquer le problème de génération PDF."""

import json
import sys
from pathlib import Path

# Test 1: Vérifier que reportlab est installé
print("[1] Test import reportlab...")
try:
    import reportlab
    print(f"    ✓ reportlab version: {reportlab.Version}")
except Exception as e:
    print(f"    ✗ Erreur: {e}")
    sys.exit(1)

# Test 2: Vérifier que le module PDF existe
print("[2] Test import pdf_report...")
try:
    from a02_security_misconfiguration.reporting.pdf_report import generate_pdf_report
    print("    ✓ Module pdf_report importé")
except Exception as e:
    print(f"    ✗ Erreur: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 3: Trouver un JSON de scan existant
print("[3] Recherche d'un scan JSON existant...")
reports_dir = Path(r"C:\Users\houss\AppData\Local\Temp\a02_reports")
json_files = list(reports_dir.glob("scan-*.json"))
if not json_files:
    print("    ✗ Aucun fichier JSON trouvé")
    sys.exit(1)

# Prendre le plus récent
json_file = max(json_files, key=lambda p: p.stat().st_mtime)
print(f"    ✓ Fichier trouvé: {json_file.name}")

# Test 4: Charger le JSON
print("[4] Chargement du JSON...")
try:
    with open(json_file, encoding='utf-8') as f:
        data = json.load(f)
    print(f"    ✓ JSON chargé ({len(data.get('results', []))} résultats)")
except Exception as e:
    print(f"    ✗ Erreur: {e}")
    sys.exit(1)

# Test 5: Générer le PDF
print("[5] Génération du PDF...")
output_pdf = reports_dir / "test_diagnostic.pdf"
try:
    result = generate_pdf_report(data, str(output_pdf))
    print(f"    ✓ PDF généré: {result}")
    print(f"    ✓ Taille: {output_pdf.stat().st_size} bytes")
except Exception as e:
    print(f"    ✗ Erreur: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n✅ Tous les tests passés !")
print(f"PDF de test: {output_pdf}")

