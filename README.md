# Security Misconfiguration Interface (OWASP A02)

Ce dépôt regroupe **deux composants** :

1. **Backend Python** : moteur de scan OWASP A02 (Security Misconfiguration) + API HTTP.
2. **Interface Web (React/Vite)** : terminal UI (`scan`, `scanmod`, `scans`) qui appelle l’API locale.

> Objectif : fournir un outil simple (UI + API) pour lancer un **full scan** ou un **scan par module** (sous-scan) et consulter les résultats.

---

## Structure du dépôt

- `Security Misconfiguration/` : backend Python (API + runner + checks)
- `Automatedsecurityaudittool/` : frontend React (Vite)

---

## Démarrage rapide

### 1) Lancer le backend (API Python)

Dans un terminal PowerShell :

```powershell
cd "Security Misconfiguration"
# si tu as un venv
.\.venv\Scripts\Activate.ps1
python api_server.py
```

API attendue : `http://127.0.0.1:8000`

Endpoints utiles :
- `GET /health`
- `GET /scans` (liste des modules disponibles)
- `POST /scan` (full scan)
- `POST /scan` (single scan) via le champ `scan=<module>` selon le mode utilisé par l'UI

### 2) Lancer le frontend (Interface)

Dans un autre terminal :

```powershell
cd "Automatedsecurityaudittool"
npm install
npm run dev
```

Ouvre ensuite l’URL affichée par Vite (souvent `http://localhost:5173`).

---

## Commandes disponibles dans l’UI

- `help` : affiche l’aide
- `scans` : liste les sous-scans/modules
- `scan <target>` : lance un **full scan** A02
- `scanmod <module> <target>` : lance un **single scan** (un module)

Exemples :
- `scan https://example.com`
- `scanmod http_methods_aggressive https://example.com`
- `scanmod port_scanner_aggressive 192.168.1.10`

---

## Notes importantes (PDF / Export)

- Le **PDF est généré uniquement via le full scan** (`scan <target>`).
- En mode `scanmod`, le bouton **Export PDF** est désactivé et un message indique que le PDF n’est pas disponible en single scan.

---

## Changements/correctifs réalisés

### 1) `scanmod` ne lançait pas d’appel API

Cause : une exception runtime côté frontend (`setActiveScanTarget` non défini) empêchait l’exécution de la requête.

Solution : suppression de l’appel fautif et validation via l’onglet Network.

### 2) Clarification PDF

Ajout d’une notification dans le terminal + désactivation du bouton Export PDF lorsque le PDF n’est pas disponible (single scan).

### 3) Dossier "Security Misconfiguration" affiché en bleu sur GitHub

Cause : le dossier était poussé comme **submodule** (gitlink `160000`).

Solution : suppression du submodule et ajout des fichiers sources réels dans le dépôt.

### 4) Fichier trop volumineux (GitHub > 100MB)

Le fichier `Security Misconfiguration/a02_security_misconfiguration/image/metasploitable.zip` dépasse la limite GitHub (100MB).

Recommandation : **ne pas versionner** ce type d’archive. Utiliser un lien de téléchargement externe ou Git LFS (si vraiment nécessaire).

---

## .gitignore

Un `.gitignore` racine est présent pour éviter de pousser :
- `node_modules/`, `dist/`, `.vite/`
- `.venv/`, `__pycache__/`, caches pytest
- rapports PDF/JSON générés

---

## Dépannage

### Le backend ne reçoit rien

Sous Windows PowerShell, `curl` est un alias de `Invoke-WebRequest`.
Utiliser plutôt :

```powershell
curl.exe http://127.0.0.1:8000/health
```

### Le port scanner timeout

Le module `port_scanner_aggressive` peut dépasser la timebox selon la cible/réseau.
Augmente `perScanTimebox` côté UI/back pour les réseaux lents.

---

## Licence

Voir les fichiers de licence/attributions dans `Automatedsecurityaudittool/ATTRIBUTIONS.md` et les README des modules.
