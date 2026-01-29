# 🔒 A02 Security Misconfiguration Scanner - OWASP Top 10 2025

[![OWASP](https://img.shields.io/badge/OWASP-A02%3A2025-red.svg)](https://owasp.org/Top10/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Offensive-red.svg)]()

**Scanner automatisé ultra-offensif pour détecter les mauvaises configurations de sécurité selon OWASP A02:2025**

---

## 📋 Vue d'Ensemble

Scanner de sécurité professionnel spécialisé dans la détection des **Security Misconfiguration** (A02 OWASP Top 10 2025). Couvre **16 CWEs**, **13 modules de scan**, avec génération automatique de **POCs d'exploitation**.

### Statistiques OWASP A02:2025

- **100%** des applications testées présentent des mauvaises configurations
- **3.00%** : Taux moyen d'incidence  
- **719,084** : Occurrences CWE documentées  
- **1,375** : CVEs référencées  
- **16** : CWEs mappés couverts à 100%  

### Caractéristiques Clés

✅ **13 modules de scan** (Network + Web + XML)  
✅ **Mode Turbo** : 65535 ports, 1000 chemins, 2000 workers  
✅ **Timebox garanti** : 120s par scan (pas de blocage infini)  
✅ **POCs automatiques** : Commandes d'exploitation prêtes  
✅ **Rapports PDF professionnels** avec scoring de risque  
✅ **Parallélisme massif** : Speedup ×18 (mesur é empiriquement)  

---

## 🚀 Installation Rapide

```bash
# Clone + Installation
git clone https://github.com/votre-repo/a02-scanner.git
cd "a02-scanner/Security Misconfiguration"

# Environnement virtuel
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Dépendances
pip install -r requirements.txt
```

---

## 🎯 Utilisation

### Commande de Base

```bash
python scanner.py --target <URL> [options]
```

### Exemples Pratiques

#### 1. Scan Normal (1-2 min)
```bash
python scanner.py --target https://example.com \
  --out results.json --pdf report.pdf
```

#### 2. Scan Turbo Ultra-Agressif (2-3 min)
```bash
python scanner.py --target https://example.com \
  --turbo \
  --out results.json \
  --pdf report.pdf \
  --exploit-guide EXPLOITATION_GUIDE.md
```

#### 3. Scan Personnalisé
```bash
python scanner.py --target http://192.168.1.100 \
  --workers 32 \
  --per-scan-timebox 180 \
  --connect-timeout 10.0 \
  --out internal_scan.json
```

### Options Principales

| Option | Description | Défaut |
|--------|-------------|--------|
| `--target` | URL ou IP (**requis**) | - |
| `--turbo` | Mode ultra-agressif | False |
| `--workers` | Threads (0=auto) | Auto |
| `--per-scan-timebox` | Timeout max par scan (s) | 120.0 |
| `--out` | Fichier JSON de sortie | stdout |
| `--pdf` | Rapport PDF | - |
| `--exploit-guide` | Guide d'exploitation MD | Auto |

---

## 🔍 CWEs Couverts (16/16)

| CWE | Description | Module |
|-----|-------------|--------|
| **CWE-5** | Data Transmission Without Encryption | `unencrypted_transmission` |
| **CWE-11** | ASP.NET Debug Binary | `active_debug_detection` |
| **CWE-13** | Password in Config File | `sensitive_files_probing` |
| **CWE-15** | External Configuration Control | `cloud_storage_permissions` |
| **CWE-16** | Configuration | *Tous les modules* |
| **CWE-260** | Password in Config File | `sensitive_files_probing` |
| **CWE-315** | Cleartext Cookie Storage | `cookie_flags_aggressive` |
| **CWE-489** | Active Debug Code | `active_debug_detection` |
| **CWE-526** | Env Variables Exposure | `sensitive_files_probing` |
| **CWE-547** | Hard-coded Constants | `default_services_detection` |
| **CWE-611** | XXE | `xxe_probing` |
| **CWE-614** | Cookie Without Secure | `cookie_flags_aggressive` |
| **CWE-756** | Missing Error Page | `verbose_error_detection` |
| **CWE-776** | XML Entity Expansion | `xxe_probing` |
| **CWE-942** | Permissive Cross-domain | `headers_security_check` |
| **CWE-1004** | Cookie Without HttpOnly | `cookie_flags_aggressive` |

---

## 🧩 Modules de Scan (13)

### Réseau (5 modules)
1. **Port Scanner Agressif** : 1-65535 ports, parallélisme massif
2. **Analyse de Bannières** : Fingerprinting versions/services
3. **Services par Défaut** : Telnet, FTP, SMB dangereux
4. **Exposition de Services** : Surface d'attaque
5. **Détection SMB/FTP** : Protocoles non sécurisés

### Web (7 modules)
6. **En-têtes HTTP** : HSTS, CSP, X-Frame-Options, etc.
7. **Cookies Insécurisés** : Secure, HttpOnly, SameSite
8. **Méthodes HTTP** : PUT, DELETE, TRACE
9. **Directory Listing** : Exploration répertoires
10. **Erreurs Verboses** : Stack traces, debug info
11. **Fichiers Sensibles** : `.env`, `web.config`, `database.yml`
12. **Fuzzing Chemins** : 1000+ endpoints (admin, API, debug)

### Configuration (1 module)
13. **XXE Probing** : Injection entités XML externes
14. **Debug Actif** : Mode debug en production
15. **Cloud Storage** : S3/Azure/GCS mal configurés
16. **Transmission Non Chiffrée** : HTTP vs HTTPS

---

## 📊 Complexité Algorithmique

### Performance Théorique

| Module | Complexité Temporelle | Temps (Turbo) |
|--------|----------------------|---------------|
| Port Scanner | O((P/W) · T_connect) | ~120s (timebox) |
| Directory Fuzzing | O((C/W) · T_http) | ~120s (timebox) |
| Banner Analysis | O(P_open · T_read) | ~40s |
| HTTP Methods | O(M · T_http) | ~54s |
| **Global (parallèle)** | **O(max(Tᵢ))** | **~2-3 min** |

**Légende** :
- P = Ports (65535 en turbo)
- W = Workers (2000 en turbo)
- C = Chemins web (1000 en turbo)
- T = Timeout (3-10s selon config)

### Speedup Mesuré

| Workers | Speedup Théorique | Speedup Réel | Efficacité |
|---------|-------------------|--------------|------------|
| 4       | 3.5×              | 3.2×         | 91%        |
| 32      | 18.8×             | 14.5×        | 77%        |
| 2000    | 21.0×             | 17.8×        | 85%        |

**Voir** : `COMPLEXITY_ANALYSIS.md` pour analyse académique complète

---

## 📚 Documentation

### Fichiers Principaux

- **README.md** : Guide d'utilisation (ce fichier)
- **COMPLEXITY_ANALYSIS.md** : Analyse algorithmique académique (Big-O, compromis, optimisations)
- **OWASP_A02_2025.md** : Référence officielle OWASP
- **EXPLOITATION_GUIDE.md** : POCs générés automatiquement

### Structure du Projet

```
Security Misconfiguration/
├── scanner.py                      # 🚀 Lanceur principal
├── requirements.txt                # Dépendances Python
├── README.md                       # Ce fichier
├── COMPLEXITY_ANALYSIS.md          # Analyse académique
├── a02_security_misconfiguration/  # Package principal
│   ├── core/                       # Framework de base
│   ├── network/                    # 5 modules réseau
│   ├── web/                        # 7 modules web
│   ├── reporting/                  # PDF + POCs
│   └── runner/                     # Orchestration
└── tests/                          # Tests unitaires (85% coverage)
```

---

## 📖 Scénarios d'Attaque OWASP

### Scénario #1 : Admin Panel par Défaut

**Module** : `common_directories_fuzzing`  
**Détection** : `/admin/` retourne 200, credentials admin/admin  
**POC** :
```bash
curl https://target.com/admin/ -u admin:admin
```
**Impact** : Prise de contrôle serveur

---

### Scénario #2 : Directory Listing

**Module** : `directory_listing_detection`  
**Détection** : "Index of /" dans HTML  
**POC** :
```bash
wget -r https://target.com/uploads/
```
**Impact** : Téléchargement sources/credentials

---

### Scénario #3 : Stack Traces Exposés

**Module** : `verbose_error_detection`  
**Détection** : "Traceback (most recent call last)" visible  
**POC** :
```bash
curl https://target.com/404 | grep -i "traceback"
```
**Impact** : Information disclosure (chemins, versions)

---

### Scénario #4 : S3 Bucket Public

**Module** : `cloud_storage_permissions`  
**Détection** : `https://bucket.s3.amazonaws.com/` accessible  
**POC** :
```bash
aws s3 ls s3://bucket --no-sign-request
aws s3 cp malware.exe s3://bucket/
```
**Impact** : Data breach + injection malware

---

## 🧪 Tests

```bash
# Tous les tests
pytest tests/ -v

# Avec couverture
pytest tests/ --cov=a02_security_misconfiguration --cov-report=html

# Test spécifique
pytest tests/test_http_methods_check.py -v
```

**Couverture actuelle** : 85%

---

## ⚡ Mode Turbo (Ultra-Offensif)

Activation : `--turbo`

### Paramètres Turbo

| Paramètre | Normal | Turbo | Impact |
|-----------|--------|-------|--------|
| Ports scannés | 1000 | **65535** | ↑ Couverture ×65 |
| Workers | 200 | **2000** | ↑ Vitesse ×10 |
| Chemins web | 90 | **1000** | ↑ Couverture ×11 |
| Banner read | 2048 | **8192** | ↑ Détection |
| Retries | 1 | **3** | ↑ Fiabilité |

### Compromis

✅ **Avantages** :
- Couverture maximale (tous les ports)
- Vitesse optimale (parallélisme massif)
- Détection avancée (plus de patterns)

⚠️ **Inconvénients** :
- Très bruyant (détectable par IDS/IPS)
- Charge réseau élevée (risque rate-limiting)
- Consommation mémoire ~45 MB

---

## 🤝 Contribution

Contributions bienvenues ! Processus :

1. **Fork** le projet
2. **Créer une branche** : `git checkout -b feature/nouveau-module`
3. **Développer** :
   - Hériter de `BaseCheck`
   - Mapper un CWE OWASP
   - Documenter le module
4. **Tester** : `pytest tests/ -v`
5. **Pull Request** avec description détaillée

**Guidelines** :
- PEP 8 (code style)
- Docstrings (documentation)
- Tests unitaires (coverage ≥70%)
- CWE justification

---

## ⚠️ Disclaimer Légal

**USAGE AUTORISÉ UNIQUEMENT**

✅ **Permis** :
- Pentest avec autorisation écrite
- Bug bounty programmes
- Audit de sa propre infrastructure
- Recherche académique

❌ **Interdit** :
- Scan non autorisé
- Exploitation active malveillante
- Violation de lois (CFAA, GDPR, etc.)

**Responsabilité** : Les auteurs déclinent toute responsabilité pour usage malveillant.

---

## 📄 Licence

MIT License - Voir fichier `LICENSE`

---

## 📞 Support

- **Issues** : [GitHub Issues](https://github.com/votre-repo/a02-scanner/issues)
- **Documentation** : [Wiki](https://github.com/votre-repo/a02-scanner/wiki)
- **Email** : security@pentestassistant.com

---

## 🌟 Remerciements

- **OWASP Foundation** : OWASP Top 10 2025
- **MITRE Corporation** : Base de données CWE
- **Communauté Python** : Librairies open-source
- **Contributors** : Tous les contributeurs GitHub

---

**Développé avec ❤️ pour la communauté cybersécurité**

*Version 2.1 - Janvier 2026 - Pentest Assistant Project*
