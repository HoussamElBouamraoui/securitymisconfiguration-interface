#!/usr/bin/env python3
"""
Menu minimal : entrer l'URL uniquement. Lancement automatique en mode ULTRA-AGRESSIF.
Usage: python menu.py   (depuis le dossier injection)
"""

import sys
import os
from pathlib import Path

# S'assurer que le dossier injection est dans le path et en cwd
_INJECTION_DIR = Path(__file__).resolve().parent
if str(_INJECTION_DIR) not in sys.path:
    sys.path.insert(0, str(_INJECTION_DIR))
os.chdir(_INJECTION_DIR)

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from colorama import Fore, Style, init
init(autoreset=True)

# Presets optionnels
PRESETS = {
    "1": "http://testphp.vulnweb.com/listproducts.php?cat=1",
    "2": "http://testphp.vulnweb.com/search.php?searchFor=test",
}


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def main_menu():
    clear_screen()
    print(f"""
{Fore.RED}+----------------------------------------------------------------------+
{Fore.RED}|{Fore.YELLOW}  INJECTIONHUNTER — Entrez l'URL cible                          {Fore.RED}  |
{Fore.RED}|{Fore.CYAN}  Scan lancé automatiquement en mode ULTRA-AGRESSIF (all + fast + exploit)  {Fore.RED}  |
{Fore.RED}+----------------------------------------------------------------------+{Style.RESET_ALL}

  Presets:
    1. testphp listproducts
    2. testphp search
    (ou entrez directement une URL)

""")
    choice = input(f"  {Fore.CYAN}URL ou choix (1/2){Style.RESET_ALL}: ").strip()
    url = choice
    if choice in PRESETS:
        url = PRESETS[choice]
    if not url or not url.startswith(("http://", "https://")):
        if choice in ("1", "2"):
            url = PRESETS.get(choice, PRESETS["1"])
        else:
            print(f"  {Fore.RED}URL invalide. Exemple: https://www.example.com/page?id=1{Style.RESET_ALL}")
            return

    # Nom du rapport basé sur le domaine
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.replace(":", "_").replace(".", "_")
    if not domain:
        domain = "rapport"
    pdf_path = f"rapport_{domain}.pdf"
    json_path = f"resultats_{domain}.json"

    # Mode agressif max : all, aggressive, fast, exploit, stealth + PDF + JSON
    argv = [
        "hunter.py", "-u", url,
        "-m", "all",
        "--aggressive", "--fast", "--exploit", "--stealth",
        "--out-json", json_path,
        "--out-pdf", pdf_path,
    ]
    print(f"\n  {Fore.GREEN}Cible:{Style.RESET_ALL} {url}")
    print(f"  {Fore.GREEN}Mode:{Style.RESET_ALL} ULTRA-AGRESSIF (all modules, fast, exploit)\n")
    sys.argv = argv
    try:
        from hunter import main
        main()
    except SystemExit as e:
        raise
    except Exception as e:
        print(f"{Fore.RED}Erreur: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrompu.{Style.RESET_ALL}")
        sys.exit(0)
