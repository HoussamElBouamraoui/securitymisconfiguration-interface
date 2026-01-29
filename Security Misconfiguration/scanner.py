#!/usr/bin/env python3
"""
🔒 A02 Security Misconfiguration Scanner - Lanceur Principal
============================================================

Lanceur simplifié pour exécuter les scans A02 OWASP Top 10 2025.
Usage: python scanner.py --target <URL> [options]
"""

import sys
import argparse
from pathlib import Path

# Ajouter le module au path
sys.path.insert(0, str(Path(__file__).parent))

from a02_security_misconfiguration.runner.run_full_aggressive import main

if __name__ == "__main__":
    # Banner
    print("""
╔═══════════════════════════════════════════════════════════════╗
║   🔒 A02 Security Misconfiguration Scanner - OWASP 2025     ║
║                                                               ║
║   Modules: 13 scans (Network + Web + XML)                    ║
║   CWEs couverts: 16 CWEs mappés                              ║
╚═══════════════════════════════════════════════════════════════╝
""")

    sys.exit(main())
