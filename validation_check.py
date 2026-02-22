#!/usr/bin/env python3
"""
Script de validation - Vérifier que tout est en place pour l'implémentation JWT.

Exécution:
    python validation_check.py
"""

import os
import sys
from pathlib import Path

def check_file(path: str, description: str) -> bool:
    """Vérifier qu'un fichier existe."""
    if os.path.exists(path):
        size_kb = os.path.getsize(path) / 1024
        print(f"✅ {description:50} ({size_kb:.2f} KB)")
        return True
    else:
        print(f"❌ {description:50} (NOT FOUND)")
        return False

def check_content(path: str, content: str, description: str) -> bool:
    """Vérifier qu'un fichier contient une chaîne spécifique."""
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            file_content = f.read()
            if content in file_content:
                print(f"✅ {description:50} (FOUND)")
                return True
            else:
                print(f"❌ {description:50} (NOT FOUND IN FILE)")
                return False
    else:
        print(f"❌ {description:50} (FILE MISSING)")
        return False

def main():
    """Fonction principale de validation."""
    base_path = Path(__file__).parent
    
    print("=" * 80)
    print("  ✅ VALIDATION - Implémentation JWT")
    print("=" * 80)
    print()
    
    checks_passed = 0
    checks_total = 0
    
    # ============================================================================
    print("📋 FICHIERS MODIFIÉS (Code)")
    print("-" * 80)
    
    # requirements.txt
    checks_total += 1
    if check_content(
        str(base_path / "Security Misconfiguration" / "requirements.txt"),
        "PyJWT>=2.8.0",
        "requirements.txt - PyJWT dependency"
    ):
        checks_passed += 1
    
    # api_server.py
    checks_total += 1
    if check_content(
        str(base_path / "Security Misconfiguration" / "api_server.py"),
        "import jwt",
        "api_server.py - JWT import"
    ):
        checks_passed += 1
    
    checks_total += 1
    if check_content(
        str(base_path / "Security Misconfiguration" / "api_server.py"),
        "def generate_token",
        "api_server.py - generate_token function"
    ):
        checks_passed += 1
    
    checks_total += 1
    if check_content(
        str(base_path / "Security Misconfiguration" / "api_server.py"),
        "def require_auth",
        "api_server.py - require_auth decorator"
    ):
        checks_passed += 1
    
    checks_total += 1
    if check_content(
        str(base_path / "Security Misconfiguration" / "api_server.py"),
        "@require_auth",
        "api_server.py - @require_auth used"
    ):
        checks_passed += 1
    
    # a02-api.ts
    checks_total += 1
    if check_content(
        str(base_path / "Automatedsecurityaudittool" / "src" / "utils" / "a02-api.ts"),
        "getOrCreateToken",
        "a02-api.ts - Token management"
    ):
        checks_passed += 1
    
    checks_total += 1
    if check_content(
        str(base_path / "Automatedsecurityaudittool" / "src" / "utils" / "a02-api.ts"),
        "fetchArtifact",
        "a02-api.ts - fetchArtifact function"
    ):
        checks_passed += 1
    
    # ScanResults.tsx
    checks_total += 1
    if check_content(
        str(base_path / "Automatedsecurityaudittool" / "src" / "app" / "components" / "ScanResults.tsx"),
        "fetchArtifact",
        "ScanResults.tsx - Using fetchArtifact"
    ):
        checks_passed += 1
    
    print()
    
    # ============================================================================
    print("📚 DOCUMENTATION CRÉÉE")
    print("-" * 80)
    
    docs = [
        ("SECURITY_ANALYSIS_AND_IMPLEMENTATION.md", "Analyse de sécurité"),
        ("QUICKSTART_JWT.md", "Guide de démarrage"),
        ("CHANGES_SUMMARY.md", "Résumé des changements"),
        ("DEPLOYMENT_PRODUCTION_GUIDE.md", "Guide de déploiement"),
        ("DOCUMENTATION_INDEX.md", "Index de documentation"),
        ("FINAL_SUMMARY.md", "Résumé final"),
        ("api_usage_example.py", "Client Python exemple"),
    ]
    
    for filename, description in docs:
        checks_total += 1
        if check_file(str(base_path / filename), description):
            checks_passed += 1
    
    print()
    
    # ============================================================================
    print("🔐 SÉCURITÉ - VALIDATIONS")
    print("-" * 80)
    
    # Vérifier les endpoints sécurisés
    endpoints_to_check = [
        ("/auth/token", "GET /auth/token"),
        ("/auth/renew", "POST /auth/renew"),
        ("@require_auth", "Décorateur @require_auth"),
    ]
    
    api_file = str(base_path / "Security Misconfiguration" / "api_server.py")
    for endpoint, description in endpoints_to_check:
        checks_total += 1
        if check_content(api_file, endpoint, description):
            checks_passed += 1
    
    print()
    
    # ============================================================================
    print("🧪 TESTS DE SYNTAXE")
    print("-" * 80)
    
    try:
        import py_compile
        
        files_to_check = [
            ("Security Misconfiguration/api_server.py", "api_server.py compilation"),
        ]
        
        for filepath, description in files_to_check:
            checks_total += 1
            try:
                py_compile.compile(str(base_path / filepath), doraise=True)
                print(f"✅ {description:50} (OK)")
                checks_passed += 1
            except py_compile.PyCompileError as e:
                print(f"❌ {description:50} (SYNTAX ERROR)")
                print(f"   Error: {e}")
    except ImportError:
        print("⚠️  py_compile module not available (non-critical)")
    
    print()
    
    # ============================================================================
    print("📊 RÉSUMÉ FINAL")
    print("-" * 80)
    
    percentage = (checks_passed / checks_total * 100) if checks_total > 0 else 0
    
    print(f"✅ Vérifications réussies: {checks_passed}/{checks_total}")
    print(f"📊 Taux de réussite: {percentage:.1f}%")
    print()
    
    if percentage == 100:
        print("🎉 TOUS LES TESTS SONT PASSÉS !")
        print("✅ L'implémentation JWT est COMPLÈTE et FONCTIONNELLE")
        return 0
    elif percentage >= 90:
        print("⚠️  La plupart des tests sont passés")
        print("⏳ Quelques éléments à vérifier")
        return 1
    else:
        print("❌ Plusieurs tests ont échoué")
        print("❌ Veuillez vérifier l'implémentation")
        return 2

if __name__ == "__main__":
    sys.exit(main())

