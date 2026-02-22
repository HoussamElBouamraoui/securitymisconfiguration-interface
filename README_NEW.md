# 🛡️ Security Misconfiguration Interface - Pentest Assistant

Interface complète de pentesting pour détecter les vulnérabilités OWASP A02 (Security Misconfiguration) via une interface terminal web interactive.

---

## 📋 Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Architecture](#architecture)
3. [Fonctionnalités](#fonctionnalités)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Utilisation](#utilisation)
7. [API Endpoints](#api-endpoints)
8. [Base de données](#base-de-données)
9. [IA intégrée](#ia-intégrée)
10. [Sécurité](#sécurité)
11. [Troubleshooting](#troubleshooting)

---

## 🎯 Vue d'ensemble

Plateforme full-stack professionnelle pour l'audit de sécurité automatisé avec :

- ✅ **Scanner A02 OWASP 2025** : détection avancée de misconfigurations
- ✅ **Interface terminal Linux-style** : expérience CLI dans le navigateur
- ✅ **Authentification JWT sécurisée** : gestion multi-utilisateurs (user/admin)
- ✅ **Base de données persistante** : PostgreSQL/SQLite avec historique complet
- ✅ **Génération de rapports** : JSON, PDF, guides d'exploitation
- ✅ **Assistant IA intégré** : analyse intelligente des vulnérabilités (Ollama)

---

## 🏗️ Architecture

### Stack technique

**Backend** :
- Python 3.9+ (Flask, SQLAlchemy, JWT)
- Scanner A02 modulaire (network + web checks)
- Génération PDF (ReportLab)
- IA locale (Ollama + deepseek-r1:8b)

**Frontend** :
- React 18 + TypeScript
- Vite (build rapide)
- TailwindCSS (UI terminal)
- Interface CLI immersive

**Base de données** :
- SQLite (par défaut) ou PostgreSQL
- Tables : users, scan_runs, findings, artifacts, audit_logs

### Structure du projet

```
securitymisconfiguration-interface/
├── Security Misconfiguration/       # Backend API + Scanner
│   ├── api_server.py               # API Flask principale
│   ├── scanner.py                  # CLI scanner standalone
│   ├── a02_security_misconfiguration/
│   │   ├── AI/                     # Prompts et clients IA
│   │   ├── core/                   # Moteur de scan
│   │   ├── database/               # Modèles SQLAlchemy
│   │   ├── network/                # Checks réseau
│   │   ├── web/                    # Checks web
│   │   ├── reporting/              # Génération rapports
│   │   └── runner/                 # Orchestration scans
│   └── instance/                   # Base SQLite
│
├── Automatedsecurityaudittool/      # Frontend React
│   ├── src/
│   │   ├── app/App.tsx             # Interface terminal
│   │   └── utils/a02-api.ts        # Client API
│   └── package.json
│
├── injection/                       # Modules annexes (A05)
└── README.md                        # Ce fichier
```

---

## ⚡ Fonctionnalités

### 🔐 Authentification & Gestion utilisateurs

- **Inscription** : création de compte avec email/username/password
- **Connexion** : login sécurisé avec token JWT (60 min)
- **Rôles** : `user` (scans perso) / `admin` (accès global)
- **Audit complet** : logs de toutes les actions (IP, user-agent, détails)

### 🎯 Scan de sécurité

**Modules disponibles** :
- `port_scanner_aggressive` : scan de ports TCP (1-65535)
- `http_methods_check` : détection de méthodes HTTP dangereuses
- `server_version_leak` : fuite de version serveur
- `directory_listing` : listage de répertoires exposés
- `sensitive_files_exposure` : fichiers sensibles accessibles
- `security_headers_missing` : headers de sécurité manquants
- `tls_weak_ciphers` : chiffrement TLS faible
- `cors_misconfiguration` : CORS mal configuré
- `csp_missing_or_weak` : CSP absent ou faible
- `xxe_prone_endpoints` : endpoints vulnérables XXE
- `default_credentials` : credentials par défaut
- `admin_panel_exposed` : panels admin exposés

**Options de scan** :
- Scan complet ou module spécifique
- Timeouts configurables
- Mode turbo (parallélisation)
- Génération PDF automatique

### 📊 Rapports automatisés

**Formats générés** :
1. **JSON** : résultats structurés machine-readable
2. **PDF** : rapport professionnel avec logo, métriques, recommandations
3. **Guide d'exploitation** : POCs Markdown prêts à l'emploi

**Contenu des rapports** :
- Score de risque global (0-100)
- Sévérité globale (INFO/LOW/MEDIUM/HIGH/CRITICAL)
- Liste détaillée des findings avec preuves
- Recommandations de remédiation
- Commandes d'exploitation prêtes à copier

### 🤖 Assistant IA (Ollama)

**Deux modes** :

1. **Analyse de rapport** : après chaque scan, l'IA propose une analyse experte
   - Résumé exécutif
   - Vulnérabilités critiques
   - Quick wins prioritaires

2. **Questions ouvertes** : commande `askai <question>`
   - Conseil en cybersécurité
   - Contexte du dernier scan
   - Refuse les questions hors domaine

**Caractéristiques** :
- Réponses en texte brut (pas de markdown)
- Concepts clés en MAJUSCULES
- Format structuré avec retours à la ligne
- Logs d'audit pour chaque interaction

### 💻 Interface terminal

**Commandes disponibles** :

| Commande | Description |
|----------|-------------|
| `help` | Affiche l'aide complète |
| `scan <target>` | Lance un scan A02 complet |
| `scanmod <module> <target>` | Lance un module spécifique |
| `scans` | Liste les modules disponibles |
| `download <scan_id>` | Télécharge un rapport PDF |
| `whoami` | Affiche les infos du user connecté |
| `askai <question>` | Pose une question à l'IA |
| `logout` | Déconnexion |
| `clear` | Efface l'écran |

**Workflow typique** :
```
> login
login: user2
password: ****
✓ Connecté avec succès

> scan http://testphp.vulnweb.com
⚙ Scan lancé...
✓ Scan terminé avec succès!
Est-ce que tu veux une analyse IA du rapport ? (oui/non)
> oui
AI: analyse du rapport en cours...
[Analyse détaillée de l'IA]

> askai comment exploiter une XXE ?
AI: réponse en cours...
[Réponse technique de l'IA]
```

---

## 🚀 Installation

### Prérequis

- **Python 3.9+** (avec pip)
- **Node.js 18+** (avec npm)
- **Ollama** (pour l'IA) : [ollama.com](https://ollama.com)
- *Optionnel* : **PostgreSQL 15+** (ou SQLite par défaut)
- *Optionnel* : **Docker** (pour PostgreSQL en container)

### Étape 1 : Backend (API + Scanner)

```powershell
cd "C:\Users\houss\Desktop\securitymisconfiguration-interface\Security Misconfiguration"

# Créer l'environnement virtuel
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Installer les dépendances
pip install -r requirements.txt

# Initialiser la base de données
python init_db.py

# Lancer l'API
python api_server.py
```

**API disponible sur** : `http://127.0.0.1:8000`

### Étape 2 : Frontend (Interface Terminal)

```powershell
cd "C:\Users\houss\Desktop\securitymisconfiguration-interface\Automatedsecurityaudittool"

# Installer les dépendances
npm install

# Lancer le serveur de dev
npm run dev
```

**Frontend disponible sur** : `http://localhost:5173`

### Étape 3 : IA (Ollama)

```powershell
# Télécharger et installer Ollama depuis https://ollama.com

# Télécharger le modèle deepseek-r1:8b
ollama pull deepseek-r1:8b

# Vérifier que le serveur Ollama tourne
# Par défaut : http://127.0.0.1:11434
```

---

## ⚙️ Configuration

### Variables d'environnement

**Backend (`api_server.py`)** :

```powershell
# Base de données (défaut: SQLite local)
$env:DATABASE_URL = "sqlite:///a02_scans.db"
# Ou PostgreSQL:
$env:DATABASE_URL = "postgresql+psycopg2://user:pass@localhost:5432/pentest_db"

# JWT
$env:JWT_SECRET_KEY = "votre-clé-secrète-production"

# Ollama
$env:OLLAMA_BASE_URL = "http://127.0.0.1:11434"
$env:OLLAMA_MODEL = "deepseek-r1:8b"

# API
$env:A02_API_HOST = "127.0.0.1"
$env:A02_API_PORT = "8000"
```

**Frontend (`vite.config.ts`)** :

```typescript
// Par défaut, l'API est sur http://127.0.0.1:8000
// Modifier VITE_API_BASE si nécessaire
```

---

## 📖 Utilisation

### Démarrage rapide

1. **Lancer le backend** :
   ```powershell
   cd ".\Security Misconfiguration"
   .\.venv\Scripts\Activate.ps1
   python api_server.py
   ```

2. **Lancer le frontend** :
   ```powershell
   cd ".\Automatedsecurityaudittool"
   npm run dev
   ```

3. **Ouvrir le navigateur** : `http://localhost:5173`

4. **Créer un compte** :
   - Taper `register` dans le terminal
   - Suivre les instructions (email, username, password)

5. **Lancer un scan** :
   ```
   > scan http://testphp.vulnweb.com
   ```

6. **Analyser avec l'IA** :
   - Répondre `oui` quand demandé après le scan
   - Ou utiliser `askai <question>` à tout moment

### Workflow complet

```
> login
login: admin
password: ****
✓ Connecté en tant que admin

> whoami
User ID: 1
Username: admin
Email: admin@example.com
Role: ADMIN
Token expires: 2026-02-22 23:00:00

> scans
Modules disponibles (12):
  - port_scanner_aggressive
  - http_methods_check
  - server_version_leak
  ...

> scan http://example.com
⚙ Scan lancé...
✓ Scan terminé avec succès!
Scan ID: 9e2034f6-6f1a-4b19-a22a-5e304913d501
Est-ce que tu veux une analyse IA du rapport ? (oui/non)

> oui
AI: analyse du rapport en cours...

RÉSUMÉ EXÉCUTIF
Ce scan révèle plusieurs MISCONFIGURATIONS critiques sur example.com...

VULNÉRABILITÉS CRITIQUES
- PORT 22 (SSH) exposé publiquement
- HEADERS DE SÉCURITÉ manquants (CSP, HSTS)
- DIRECTORY LISTING activé sur /uploads/

QUICK WINS
- Ajouter les headers de sécurité
- Désactiver le directory listing
- Restreindre les ports exposés

> download 9e2034f6-6f1a-4b19-a22a-5e304913d501
✓ Téléchargement du rapport PDF...

> askai comment exploiter une XXE ?
AI: réponse en cours...

XXE (XML EXTERNAL ENTITY)

Définition:
Une XXE permet d'injecter des entités XML externes pour lire des fichiers locaux...
```

---

## 🔌 API Endpoints

### Authentification

| Méthode | Endpoint | Description | Auth requise |
|---------|----------|-------------|--------------|
| `POST` | `/auth/register` | Créer un compte | Non |
| `POST` | `/auth/login` | Se connecter | Non |
| `POST` | `/auth/renew` | Renouveler le token | Oui |
| `GET` | `/auth/me` | Infos du token | Oui |
| `GET` | `/auth/token` | Token système (debug) | Non |

**Exemple de login** :
```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

**Réponse** :
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "type": "Bearer",
  "expiresIn": 3600
}
```

### Scans

| Méthode | Endpoint | Description | Auth requise |
|---------|----------|-------------|--------------|
| `GET` | `/scans` | Liste des modules | Oui |
| `POST` | `/scan` | Lancer un scan | Oui |
| `GET` | `/api/history` | Historique des scans | Oui |

**Exemple de scan** :
```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://example.com",
    "connectTimeout": 3,
    "readTimeout": 6,
    "generatePdf": true
  }'
```

### Rapports

| Méthode | Endpoint | Description | Auth requise |
|---------|----------|-------------|--------------|
| `GET` | `/reports/<scan_id>.json` | Rapport JSON | Oui |
| `GET` | `/reports/<scan_id>.pdf` | Rapport PDF | Oui |
| `GET` | `/reports/<scan_id>_EXPLOITATION_GUIDE.md` | Guide d'exploitation | Oui |

### IA

| Méthode | Endpoint | Description | Auth requise |
|---------|----------|-------------|--------------|
| `POST` | `/ai/chat` | Dialoguer avec l'IA | Oui |

**Modes disponibles** :
- `mode: "report"` : analyse d'un rapport de scan
- `mode: "ask"` : question ouverte

**Exemple** :
```bash
curl -X POST http://127.0.0.1:8000/ai/chat \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "ask",
    "question": "Comment exploiter une XXE ?",
    "language": "fr"
  }'
```

---

## 🗄️ Base de données

### Tables principales

**`users`**
- `id` (PK)
- `email` (unique)
- `username` (unique)
- `password_hash` (bcrypt)
- `role` (`user` / `admin`)
- `created_at`

**`scan_runs`**
- `id` (PK)
- `user_id` (FK → users)
- `target` (URL/IP scanné)
- `scan_type` (A02 / A02:module)
- `status` (RUNNING / DONE / ERROR)
- `started_at`, `finished_at`
- `parameters_json` (config du scan)
- `summary_json` (résumé)
- `error_message`

**`artifacts`**
- `id` (PK)
- `scan_id` (FK → scan_runs)
- `type` (`json` / `pdf` / `md`)
- `path` (chemin relatif)
- `created_at`

**`audit_logs`**
- `id` (PK)
- `user_id` (FK → users)
- `scan_id` (FK → scan_runs, nullable)
- `action` (SCAN_START, SCAN_DONE, AI_ASK, etc.)
- `ip`, `user_agent`
- `details` (JSON)
- `created_at`

### Configuration PostgreSQL

```powershell
# Lancer PostgreSQL via Docker
docker run --name pentest-db `
  -e POSTGRES_PASSWORD=postgres `
  -e POSTGRES_DB=pentest_assistant `
  -p 5432:5432 -d postgres:15

# Configurer la variable d'environnement
$env:DATABASE_URL = "postgresql+psycopg2://postgres:postgres@localhost:5432/pentest_assistant"

# Installer le driver
pip install psycopg2-binary

# Initialiser la base
python init_db.py
```

---

## 🤖 IA intégrée

### Configuration Ollama

1. **Installer Ollama** : [https://ollama.com](https://ollama.com)

2. **Télécharger le modèle** :
   ```powershell
   ollama pull deepseek-r1:8b
   ```

3. **Vérifier que le serveur tourne** :
   ```powershell
   curl http://127.0.0.1:11434/api/version
   ```

### Utilisation de l'IA

**Dans le terminal** :

1. **Après un scan** : l'IA propose automatiquement une analyse
   ```
   Est-ce que tu veux une analyse IA du rapport ? (oui/non)
   > oui
   ```

2. **Question libre** :
   ```
   > askai comment exploiter une XXE ?
   > askai donne-moi les quick wins pour sécuriser nginx
   ```

**Caractéristiques** :
- ✅ Réponses en texte brut (pas de markdown)
- ✅ Concepts clés en MAJUSCULES (OWASP, SQL, XSS...)
- ✅ Structure claire avec retours à la ligne
- ✅ Refuse les questions hors cybersécurité
- ✅ Contexte du dernier scan automatiquement injecté

**Localisation des prompts** :
- `Security Misconfiguration/api_server.py` (lignes ~620 et ~670)
- `Security Misconfiguration/a02_security_misconfiguration/AI/prompts.py`

---

## 🔒 Sécurité

### Authentification JWT

- **Algorithme** : HS256
- **Expiration** : 60 minutes
- **Payload** : `user_id`, `role`, `iat`, `exp`
- **Stockage** : localStorage (frontend) + header Authorization (backend)

### Hashage des mots de passe

- **Bibliothèque** : bcrypt
- **Rounds** : 12 (par défaut)
- **Salage** : automatique

### Protection des endpoints

Tous les endpoints sensibles sont protégés par le décorateur `@require_auth` :
- `/scan`
- `/reports/*`
- `/ai/chat`
- `/auth/renew`
- `/auth/me`

### Audit et traçabilité

Chaque action est loguée dans `audit_logs` :
- User ID
- IP source
- User-Agent
- Action (SCAN_START, SCAN_DONE, AI_ASK, etc.)
- Détails JSON
- Timestamp

### CORS

Le backend accepte toutes les origines en développement. **En production**, restreindre via :
```python
CORS(app, resources={r"/*": {"origins": ["https://votre-domaine.com"]}})
```

### Recommandations production

1. **JWT_SECRET_KEY** : générer une clé forte aléatoire
2. **DATABASE_URL** : utiliser PostgreSQL avec SSL
3. **HTTPS** : reverse proxy (nginx/caddy) avec certificat
4. **Rate limiting** : ajouter Flask-Limiter
5. **CSP** : ajouter Content-Security-Policy headers
6. **HSTS** : forcer HTTPS strict
7. **Secrets** : utiliser un gestionnaire de secrets (Vault, AWS Secrets)

---

## 🐛 Troubleshooting

### Erreur : Token invalide ou expiré

**Symptôme** : `401` sur `/ai/chat` ou `/scan`

**Solution** :
```
> logout
> login
```

### Erreur : PDF non généré

**Symptôme** : `✗ PDF non généré côté serveur`

**Cause** : Encodage console Windows ou timeout

**Solution** :
```powershell
$env:PYTHONUTF8 = "1"
python api_server.py
```

### Erreur : ModuleNotFoundError: No module named 'psycopg2'

**Symptôme** : Erreur au démarrage avec PostgreSQL

**Solution** :
```powershell
pip install psycopg2-binary
```

### Erreur : NOT NULL constraint failed: scan_runs.user_id

**Symptôme** : Erreur lors d'un scan

**Cause** : Token expiré ou session restaurée avec ancien token

**Solution** :
```
> logout
> login
> scan <target>
```

### Erreur : IA renvoie du markdown ou des caractères chinois

**Symptôme** : Réponse avec `**texte**` ou caractères unicode bizarres

**Solution** : Le nettoyage automatique dans `clean_ai_response()` est actif. Si le problème persiste :
1. Vérifier que Ollama utilise bien `deepseek-r1:8b`
2. Redémarrer le serveur API
3. Essayer un autre modèle : `ollama pull llama3`

### IA ne répond pas

**Symptôme** : Timeout ou erreur lors de `askai`

**Solution** :
1. Vérifier que Ollama tourne : `curl http://127.0.0.1:11434/api/version`
2. Vérifier le modèle : `ollama list`
3. Augmenter le timeout dans `api_server.py` (ligne `timeout=300`)

### Session restaurée mais mauvais user_id

**Symptôme** : Les scans sont créés avec user_id=1 au lieu de l'utilisateur connecté

**Solution** : Faire un logout/login complet (pas de restauration de session)
```
> logout
> login
```

---

## 📚 Documentation technique

Pour une analyse approfondie de la complexité algorithmique et des optimisations, voir :

📄 **`Security Misconfiguration/COMPLEXITY_ANALYSIS.md`**

---

## 🤝 Contribution

Ce projet est conçu pour un usage personnel/éducatif. Pour contribuer :

1. Fork le projet
2. Créer une branche feature
3. Commit les changements
4. Ouvrir une Pull Request

---

## ⚠️ Avertissement légal

**Cet outil est conçu pour des tests d'intrusion autorisés uniquement.**

- ❌ N'utilisez JAMAIS cet outil sur des systèmes sans autorisation écrite
- ✅ Utilisez-le uniquement sur vos propres systèmes ou avec autorisation explicite
- ⚖️ L'utilisation non autorisée peut violer des lois (CFAA, RGPD, etc.)

**L'auteur décline toute responsabilité en cas d'usage malveillant.**

---

## 📝 Licence

Voir le fichier `LICENSE` si présent. Usage éducatif et professionnel autorisé.

---

## 📞 Support

Pour toute question technique :
- 📂 Consulter `COMPLEXITY_ANALYSIS.md`
- 🐛 Vérifier les logs backend (terminal Python)
- 💬 Utiliser la commande `help` dans l'interface

---

**Développé avec ❤️ pour la communauté cybersécurité**

