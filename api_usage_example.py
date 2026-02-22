#!/usr/bin/env python3
"""
Exemple d'utilisation de l'API A02 avec authentification JWT.

Usage:
    python api_usage_example.py <target> [--module <module_name>]

Exemple:
    python api_usage_example.py example.com
    python api_usage_example.py 192.168.1.1 --module port_scanner_aggressive
"""

import requests
import json
import argparse
import time
from typing import Optional, Dict, Any

# Configuration
API_BASE = "http://127.0.0.1:8000"


class A02ScannerClient:
    """Client Python pour l'API A02 avec authentification JWT."""

    def __init__(self, api_base: str = API_BASE):
        self.api_base = api_base
        self.token: Optional[str] = None
        self.session = requests.Session()

    def get_token(self) -> str:
        """Obtient un nouveau token JWT."""
        print("[*] Requête d'un token JWT...")

        response = self.session.get(f"{self.api_base}/auth/token")
        response.raise_for_status()

        data = response.json()
        self.token = data["token"]

        print(f"[✓] Token obtenu (expire dans {data['expiresIn']} secondes)")
        print(f"    Token: {self.token[:50]}...")

        return self.token

    def renew_token(self) -> str:
        """Renouvelle un token JWT."""
        if not self.token:
            return self.get_token()

        print("[*] Renouvellement du token JWT...")

        headers = {"Authorization": f"Bearer {self.token}"}
        response = self.session.post(f"{self.api_base}/auth/renew", headers=headers)

        if response.status_code == 401:
            print("[!] Token expiré, obtention d'un nouveau...")
            return self.get_token()

        response.raise_for_status()
        data = response.json()
        self.token = data["token"]

        print(f"[✓] Token renouvelé")

        return self.token

    def _ensure_token(self) -> str:
        """Assure qu'un token valide est disponible."""
        if not self.token:
            self.get_token()
        return self.token

    def _get_headers(self) -> Dict[str, str]:
        """Retourne les headers avec authentification JWT."""
        token = self._ensure_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def health_check(self) -> bool:
        """Vérifie la disponibilité de l'API."""
        print("[*] Vérification de la santé de l'API...")

        try:
            response = self.session.get(f"{self.api_base}/health")
            response.raise_for_status()
            print("[✓] API disponible")
            return True
        except Exception as e:
            print(f"[✗] Erreur: {e}")
            return False

    def get_available_scans(self) -> list:
        """Récupère la liste des modules de scan disponibles."""
        print("[*] Récupération de la liste des modules...")

        headers = self._get_headers()
        response = self.session.get(f"{self.api_base}/scans", headers=headers)
        response.raise_for_status()

        data = response.json()
        scans = data["scans"]

        print(f"[✓] {len(scans)} modules disponibles:")
        for scan in scans[:10]:  # Afficher les 10 premiers
            print(f"    - {scan}")
        if len(scans) > 10:
            print(f"    ... et {len(scans) - 10} autres")

        return scans

    def run_full_scan(self, target: str, generate_pdf: bool = False) -> Dict[str, Any]:
        """Lance un scan A02 complet sur la cible."""
        print(f"\n[*] Lancement d'un scan complet sur {target}...")

        payload = {
            "target": target,
            "connectTimeout": 3.0,
            "readTimeout": 6.0,
            "retries": 1,
            "perScanTimebox": 120,
            "turbo": False,
            "generatePdf": generate_pdf
        }

        headers = self._get_headers()
        response = self.session.post(
            f"{self.api_base}/scan",
            json=payload,
            headers=headers,
            timeout=300  # 5 minutes timeout
        )
        response.raise_for_status()

        data = response.json()
        print(f"[✓] Scan complété!")
        print(f"    Scan ID: {data.get('scan_id')}")
        print(f"    Résultats: {len(data.get('results', []))} modules")

        return data

    def run_module_scan(self, module: str, target: str) -> Dict[str, Any]:
        """Lance un scan d'un module spécifique."""
        print(f"\n[*] Lancement du scan du module '{module}' sur {target}...")

        payload = {
            "target": target,
            "scan": module,
            "connectTimeout": 3.0,
            "readTimeout": 6.0,
            "retries": 1,
            "perScanTimebox": 60
        }

        headers = self._get_headers()
        response = self.session.post(
            f"{self.api_base}/scan",
            json=payload,
            headers=headers,
            timeout=120  # 2 minutes timeout
        )
        response.raise_for_status()

        data = response.json()
        print(f"[✓] Scan complété!")
        print(f"    Scan ID: {data.get('scan_id')}")

        return data

    def get_report(self, scan_id: str, format: str = "json") -> Optional[bytes]:
        """Télécharge un rapport."""
        print(f"[*] Téléchargement du rapport ({format})...")

        headers = self._get_headers()

        if format == "json":
            url = f"{self.api_base}/reports/{scan_id}.json"
        elif format == "pdf":
            url = f"{self.api_base}/reports/{scan_id}.pdf"
        else:
            print(f"[✗] Format inconnu: {format}")
            return None

        response = self.session.get(url, headers=headers)

        if response.status_code == 404:
            print(f"[!] Rapport non trouvé (scan_id={scan_id})")
            return None

        response.raise_for_status()

        print(f"[✓] Rapport téléchargé ({len(response.content)} octets)")

        return response.content

    def save_report(self, scan_id: str, filename: str, format: str = "json") -> bool:
        """Télécharge et sauvegarde un rapport."""
        content = self.get_report(scan_id, format)
        if content is None:
            return False

        with open(filename, "wb") as f:
            f.write(content)

        print(f"[✓] Rapport sauvegardé: {filename}")
        return True


def main():
    """Fonction principale."""
    parser = argparse.ArgumentParser(
        description="Client pour l'API A02 Security Misconfiguration",
        epilog="Exemples:\n"
               "  python api_usage_example.py example.com\n"
               "  python api_usage_example.py 192.168.1.1 --module port_scanner_aggressive\n"
               "  python api_usage_example.py example.com --pdf",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("target", help="Cible du scan (URL, hostname, IP)")
    parser.add_argument("--module", help="Lancer un scan d'un module spécifique (optionnel)")
    parser.add_argument("--pdf", action="store_true", help="Générer un PDF (full scan uniquement)")
    parser.add_argument("--save", help="Sauvegarder le rapport (ex: ./scan_results)")
    parser.add_argument("--api", default=API_BASE, help=f"URL de l'API (défaut: {API_BASE})")

    args = parser.parse_args()

    # Créer le client
    client = A02ScannerClient(args.api)

    print("=" * 70)
    print("  A02 Security Misconfiguration Scanner - Client Python")
    print("  Avec authentification JWT")
    print("=" * 70)

    # Vérifier l'API
    if not client.health_check():
        print("\n[✗] L'API n'est pas accessible. Veuillez lancer:")
        print(f"    cd \"Security Misconfiguration\" && python api_server.py")
        return 1

    print()

    # Obtenir un token
    try:
        client.get_token()
    except Exception as e:
        print(f"[✗] Erreur lors de l'obtention du token: {e}")
        return 1

    print()

    # Lister les modules
    try:
        client.get_available_scans()
    except Exception as e:
        print(f"[✗] Erreur lors de la récupération des modules: {e}")
        return 1

    print()

    # Lancer le scan
    try:
        if args.module:
            result = client.run_module_scan(args.module, args.target)
        else:
            result = client.run_full_scan(args.target, generate_pdf=args.pdf)
    except Exception as e:
        print(f"[✗] Erreur lors du scan: {e}")
        return 1

    print()

    # Afficher les résultats
    scan_id = result.get("scan_id")
    print(f"[*] Résumé du scan:")
    print(f"    Scan ID: {scan_id}")
    print(f"    Target: {result.get('target', {}).get('hostname', 'N/A')}")
    print(f"    Status: {result.get('status', 'N/A')}")

    # Sauvegarder le rapport si demandé
    if args.save:
        print()
        try:
            base_path = args.save
            client.save_report(scan_id, f"{base_path}.json", "json")

            if args.pdf and result.get("artifacts", {}).get("pdf"):
                client.save_report(scan_id, f"{base_path}.pdf", "pdf")
        except Exception as e:
            print(f"[✗] Erreur lors de la sauvegarde: {e}")
            return 1

    print("\n[✓] Opération complétée avec succès!")
    print()

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

