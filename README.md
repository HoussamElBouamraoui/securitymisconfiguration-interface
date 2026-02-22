# Security Misconfiguration Interface

Projet full-stack pour piloter un scanner A02 (OWASP 2025) via une interface terminal web.

## Vue d'ensemble

- **Backend**: API Flask locale (scan, auth JWT, rapports JSON/PDF).
- **Scanner**: modules A02 (network + web) avec sortie agrégée.
- **Frontend**: UI terminal (React/Vite) pour login, scan, export, logs.
- **DB**: persistance des scans, logs, artifacts.

## Architecture (haut niveau)

- **Frontend**: UI terminal (React/Vite) qui parle à l’API via `/api`.
- **API Backend**: Flask (auth JWT, orchestration des scans, artefacts).
- **Scanner A02**: modules réseau/web exécutés en sous‑processus.
- **Stockage**: SQLite par défaut, PostgreSQL possible via `DATABASE_URL`.
- **Artefacts**: JSON, PDF, guide d’exploitation servis par l’API (JWT requis).

## Endpoints API (principaux)

### Auth

- `POST /auth/register` : créer un compte
- `POST /auth/login` : se connecter
- `POST /auth/renew` : renouveler le token
- `GET /auth/me` : infos du token (debug)

### Scan

- `GET /scans` : liste des modules disponibles
- `POST /scan` : lancer un scan (full ou module)

### Rapports

- `GET /reports/<scan_id>.json`
- `GET /reports/<scan_id>.pdf`
- `GET /reports/<scan_id>_EXPLOITATION_GUIDE.md`

## Structure du projet

- `Security Misconfiguration/` : backend + scanner A02
- `Automatedsecurityaudittool/` : frontend Vite/React
- `injection/` : modules/outils annexes
- `README.md` (ce fichier)
- `Security Misconfiguration/COMPLEXITY_ANALYSIS.md` : doc technique conservée

## Prérequis

- Python 3.9+
- Node.js 18+
- (Optionnel) PostgreSQL 15+ ou SQLite local

## Installation rapide

### Backend (API + Scanner)

```powershell
cd "C:\Users\houss\Desktop\securitymisconfiguration-interface\Security Misconfiguration"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python api_server.py
```

### Frontend (UI Terminal)

```powershell
cd "C:\Users\houss\Desktop\securitymisconfiguration-interface\Automatedsecurityaudittool"
npm install
npm run dev
```

- API par défaut: `http://127.0.0.1:8000`
- Frontend par défaut: `http://localhost:5173`

## Authentification (JWT)

- **Login**: `/auth/login`
- **Register**: `/auth/register`
- **Renew**: `/auth/renew`
- **Me** (debug): `/auth/me`

Le token JWT est stocké dans `localStorage` et utilisé pour tous les appels protégés.

## Commandes dans l'UI Terminal

- `scan <target>` : scan A02 complet
- `scanmod <module> <target>` : sous-scan spécifique
- `scans` : liste des modules disponibles
- `whoami` : infos utilisateur connecté
- `logout` : déconnexion
- `help` : aide

## Rapports

- JSON: `/reports/<scan_id>.json`
- PDF: `/reports/<scan_id>.pdf`
- Guide: `/reports/<scan_id>_EXPLOITATION_GUIDE.md`

Les rapports sont générés côté backend et servis par l'API avec authentification JWT.

## Base de données

Par défaut, l'API utilise SQLite local. Pour PostgreSQL:

```powershell
$env:DATABASE_URL = "postgresql+psycopg2://postgres:postgres@localhost:5432/pentest_assistant"
python api_server.py
```

## Lancer un scan en CLI (optionnel)

```powershell
cd "C:\Users\houss\Desktop\securitymisconfiguration-interface\Security Misconfiguration"
python scanner.py --target https://example.com --out results.json --pdf report.pdf
```

## Notes importantes

- Le PDF est généré côté serveur via `reportlab`.
- Les endpoints `/reports/*` sont protégés par JWT.
- En cas de token expiré, reconnectez-vous via le terminal UI.

## Troubleshooting rapide

- **401 sur PDF**: reconnectez-vous pour obtenir un token valide.
- **PDF non généré**: relancez un scan complet, puis vérifiez les logs backend.
- **Session restaurée mais mauvais user_id**: reconnectez-vous (token expiré).

## Licence

Voir le fichier de licence du projet si présent.

