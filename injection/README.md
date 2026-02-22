cd inj# InjectionHunter — OWASP Top 10 A05:2025 Injection

Scanner de vulnerabilites d'injection aligne sur **OWASP Top 10 A05:2025** (37 CWEs, 62k+ CVEs).  
Usage **strictement autorise** (sites avec consentement ecrit).

## Alignement OWASP A05:2025

- **CWE couverts** : CWE-89 (SQLi), CWE-79/80/83 (XSS), CWE-78/77 (CMDi), CWE-90 (LDAP), CWE-91/643 (XPath), CWE-94/95/96 (Code/Eval), CWE-98 (LFI), CWE-610 (SSRF), CWE-564 (ORM), CWE-917 (EL), etc.
- **Types** : SQL/NoSQL, XSS, Command Injection, LFI, LDAP, XPath, ORM, SSTI, SSRF, Deserialization, WebSocket, Config/ASVS.
- **References** : `constants.py` (CWE, parametres par defaut), `reporting/a05_aggregator.py` (CWE dans les findings PDF).

## Lancement

**Menu interactif (recommandé)** — choisir la cible, les modules et les options puis lancer :

```bash
cd injection
python menu.py
```

**Ligne de commande** :

```bash
# Scan complet (URL avec parametres recommande)
python hunter.py -u "https://example.com/page?id=1" -m all --stealth

# Mode ULTRA-AGRESSIF (evasion WAF + payloads polymorphiques)
python hunter.py -u "https://example.com/page?id=1" -m sqli,xss,cmdi --aggressive --stealth

# Mode RAPIDE (timeouts courts, parallelo, moins de requetes)
python hunter.py -u "https://example.com/page?id=1" -m sqli,xss --fast --stealth

# Phase exploitation (apres detection: tenter extraction version/DB pour SQLi, etc.)
python hunter.py -u "https://example.com/page?id=1" -m sqli,xss --exploit --stealth

# Test sur cibles AUTORISEES uniquement
python hunter.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -m sqli --stealth --test-authorized
```

## Test sur sites autorises

**Site de test recommande** : [testphp.vulnweb.com](http://testphp.vulnweb.com/) (Acunetix, volontairement vulnerable).

```bash
# Test complet sur une URL (SQLi, XSS, CMDi, LFI, forms, admin) + export JSON
python hunter.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -m sqli,xss,cmdi,lfi,forms,admin --stealth --test-authorized --out-json report.json

# XSS reflete (GET + POST) : tester aussi search.php
python hunter.py -u "http://testphp.vulnweb.com/search.php?searchFor=test" -m xss,sqli --stealth --test-authorized
```

Pour n'accepter que des URLs dans une liste blanche :

```bash
python hunter.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --test-authorized -m sqli,xss --stealth

set INJECTION_ALLOWED_TARGETS=http://localhost:8080,http://dvwa.local
python hunter.py -u "http://localhost:8080/app?id=1" --test-authorized -m all --stealth
```

Scripts dedies (depuis la racine du repo ou `injection/`) :

```bash
python -m injection.tests.run_authorized_scan --url "http://testphp.vulnweb.com/listproducts.php?cat=1" --modules sqli,xss,forms
python -m injection.tests.run_full_test_testphp --out testphp_full_report.json
```

## Modules

| Module | Description |
|--------|-------------|
| sqli | SQL Injection (blind, time-based, error-based, union, NoSQL) |
| xss | Cross-Site Scripting (polyglot) |
| cmdi | Command Injection / RCE |
| lfi | Local File Inclusion / Path Traversal |
| ldap | LDAP Injection |
| xpath | XPath Injection |
| orm | ORM (Hibernate, etc.) |
| template | Server-Side Template Injection (SSTI) |
| ssrf | Server-Side Request Forgery |
| deserialization | Deserialization (PHP, Java, Python, .NET) |
| websocket | WebSocket Injection |
| forms | Analyse des formulaires |
| admin | Recherche panneaux admin |
| cms | Detection CMS |
| cookies | Analyse cookies/sessions |
| config | Config Auditor |
| asvs | ASVS Compliance |

## Export JSON et rapport PDF

```bash
# Exporter les vulns en JSON (depuis hunter)
python hunter.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -m all --stealth --out-json vulns.json

# Generer un PDF a partir du JSON
python -m injection.reporting.cli --in vulns.json --out report.pdf --target "http://cible.com"
```

Les findings incluent le **CWE** associe (mapping dans `constants.VULN_TYPE_TO_CWE`).

## Performance et intelligence

- **--fast** : timeouts courts (5s), parallelo (6 workers), premier passage rapide sur XSS/CMDi/LFI. Idéal pour scans rapides.
- **--exploit** : après une détection (ex. SQLi), tente une requête d’exploitation (ex. UNION SELECT version/database) pour enrichir la preuve dans le rapport.
- **SQLi** : ordre intelligent (erreur → booléen → union → time-based), détection du backend (MySQL/PostgreSQL/MSSQL/Oracle/SQLite) depuis les messages d’erreur, parallélisation des payloads non time-based.
- **XSS/CMDi/LFI** : payloads « rapides » en premier, puis pass complet si besoin ; utilisation du timeout et de `engine.get()` du moteur.
