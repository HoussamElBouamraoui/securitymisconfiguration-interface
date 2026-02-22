"""API locale pour relier l'interface web (Vite/React) au scanner A02.

Objectif:
- Exposer un endpoint HTTP simple /scan qui exécute le runner existant et renvoie du JSON.
- Optionnel: générer un PDF et le servir.

Conçu pour un usage local (127.0.0.1) et une intégration UI.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import traceback
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional
from functools import wraps

import jwt
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

# Les runners sont exécutés via subprocess (ne pas importer main() ici)
from a02_security_misconfiguration.registry import CHECKS


def _safe_float(v: Any, default: float) -> float:
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


def _safe_int(v: Any, default: int) -> int:
    try:
        if v is None:
            return default
        return int(v)
    except Exception:
        return default


# Clé secrète pour JWT (utiliser une variable d'env en production!)
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRATION_MINUTES = 60


def generate_token(app_key: str = None) -> str:
    """Génère un token JWT valide pour 1 heure."""
    payload = {
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES),
        "type": "scanner_token"
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> Dict[str, Any] | None:
    """Vérifie et décode un token JWT. Retourne le payload ou None si invalide."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    """Décorateur pour vérifier l'authentification via token JWT dans le header Authorization."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        # Format: "Bearer <token>"
        if not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Authentification requise",
                "message": "Veuillez fournir un token JWT via le header 'Authorization: Bearer <token>'",
                "hint": "Obtenez un token via GET /auth/token"
            }), 401

        token = auth_header[7:]  # Enlever "Bearer "

        payload = verify_token(token)
        if payload is None:
            return jsonify({
                "error": "Token invalide ou expiré",
                "message": "Le token JWT n'est pas valide ou a expiré"
            }), 401

        # Passer le payload au endpoint
        request.jwt_payload = payload
        return f(*args, **kwargs)

    return decorated_function


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})

    import sys
    python_exe = sys.executable

    reports_dir = Path(tempfile.gettempdir()) / "a02_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    @app.get("/auth/token")
    def get_token():
        """Endpoint public pour obtenir un token JWT (accès local seulement recommandé)."""
        token = generate_token()
        return jsonify({
            "token": token,
            "type": "Bearer",
            "expiresIn": TOKEN_EXPIRATION_MINUTES * 60,  # en secondes
            "message": "Utilisez ce token dans le header 'Authorization: Bearer <token>' pour les appels suivants"
        })

    @app.post("/auth/renew")
    @require_auth
    def renew_token():
        """Endpoint sécurisé pour renouveler un token (avec token valide)."""
        new_token = generate_token()
        return jsonify({
            "token": new_token,
            "type": "Bearer",
            "expiresIn": TOKEN_EXPIRATION_MINUTES * 60
        })

    @app.get("/health")
    def health():
        """Endpoint health check (pas d'authentification requise)."""
        return jsonify({"status": "ok", "version": "1.0.0"})

    @app.get("/scans")
    @require_auth
    def scans():
        # Liste officielle des sous-scans disponibles côté backend.
        return jsonify({
            "count": len(CHECKS),
            "scans": sorted(CHECKS.keys())
        })

    @app.post("/scan")
    @require_auth
    def scan():
        payload = request.get_json(silent=True) or {}
        target = (payload.get("target") or "").strip()
        if not target:
            return jsonify({"error": "target requis"}), 400

        # Option UI: exécuter un module seul (ou une liste de modules).
        # - Compat: accepte `scan` (string) ou `scans` (liste de strings).
        # - Ex: {"target":"example.com","scan":"port_scanner_aggressive"}
        scan_name = (payload.get("scan") or "").strip()
        scans_list = payload.get("scans")
        if not scan_name and isinstance(scans_list, list) and scans_list:
            # on prend le premier pour l’instant (runner single)
            scan_name = str(scans_list[0]).strip()

        connect_timeout = _safe_float(payload.get("connectTimeout"), 3.0)
        read_timeout = _safe_float(payload.get("readTimeout"), 6.0)
        retries = _safe_int(payload.get("retries"), 1)
        workers = _safe_int(payload.get("workers"), 0)
        per_scan_timebox = _safe_float(payload.get("perScanTimebox"), 300.0)
        turbo = bool(payload.get("turbo", False))
        generate_pdf = bool(payload.get("generatePdf", False))

        scan_id = str(uuid.uuid4())
        json_path = reports_dir / f"scan-{scan_id}.json"
        pdf_path: Optional[Path] = (reports_dir / f"scan-{scan_id}.pdf") if generate_pdf else None
        exploit_md_path = reports_dir / f"scan-{scan_id}_EXPLOITATION_GUIDE.md"

        # Capturer stdout/stderr du runner pour debug (renvoyé seulement si souci PDF)
        last_stdout = ""
        last_stderr = ""

        if scan_name:
            if scan_name not in CHECKS:
                return jsonify({
                    "error": "scan inconnu",
                    "scan": scan_name,
                    "availableScans": sorted(CHECKS.keys()),
                }), 400
            # Runner "single" : un sous-scan.
            # NB: run_single ne gère pas PDF/guide; l’UI peut quand même afficher le résultat.
            # On écrit un JSON wrapper côté API pour garder un format stable côté front.
            single_tmp = reports_dir / f"scan-{scan_id}_single.json"
            argv = [
                "--target",
                target,
                "--connect-timeout",
                str(connect_timeout),
                "--read-timeout",
                str(read_timeout),
                "--retries",
                str(retries),
                "--per-scan-timebox",
                str(per_scan_timebox),
                "--scan",
                scan_name,
                "--out",
                str(single_tmp),
            ]
            # Isolation via sous-processus: évite les effets de bord (argparse/sys.exit/news futures after shutdown).
            cmd = [
                python_exe,
                "-m",
                "a02_security_misconfiguration.runner.run_single",
                *argv,
            ]
            try:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=max(30.0, float(per_scan_timebox) + 20.0))
            except Exception as e:
                return jsonify({
                    "error": "exception pendant l'exécution du sous-processus",
                    "scan": scan_name,
                    "type": type(e).__name__,
                    "message": str(e),
                    "traceback": traceback.format_exc(),
                }), 500

            last_stdout = (cp.stdout or "")
            last_stderr = (cp.stderr or "")

            if cp.returncode != 0:
                return jsonify({
                    "error": "scan échouée",
                    "exitCode": cp.returncode,
                    "scan": scan_name,
                    "stderr": (cp.stderr or "")[-4000:],
                    "stdout": (cp.stdout or "")[-4000:],
                }), 500

            try:
                single_data: Dict[str, Any] = json.loads(single_tmp.read_text(encoding="utf-8"))
            except Exception as e:
                return jsonify({"error": f"impossible de lire le JSON: {type(e).__name__}: {e}"}), 500

            # Wrapper minimal compatible avec `mapRunnerJsonToAggregatedResults`.
            data: Dict[str, Any] = {
                "scan_id": scan_id,
                "target": target,
                "status": single_data.get("status", "COMPLETED"),
                "mode": "single",
                "results": [single_data],
                "artifacts": {"json": f"/reports/{scan_id}.json"},
            }
            json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            argv = [
                "--target",
                target,
                "--connect-timeout",
                str(connect_timeout),
                "--read-timeout",
                str(read_timeout),
                "--retries",
                str(retries),
                "--per-scan-timebox",
                str(per_scan_timebox),
                "--out",
                str(json_path),
            ]
            if workers:
                argv += ["--workers", str(workers)]
            if turbo:
                argv += ["--turbo"]
            if pdf_path is not None:
                argv += ["--pdf", str(pdf_path)]
            # Toujours demander la génération du guide d'exploitation (MD)
            argv += ["--exploit-guide", str(exploit_md_path)]

            cmd = [
                python_exe,
                "-m",
                "a02_security_misconfiguration.runner.run_full_aggressive",
                *argv,
            ]
            try:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=max(60.0, float(per_scan_timebox) * 2 + 60.0))
            except Exception as e:
                return jsonify({
                    "error": "exception pendant l'exécution du scan complet (sous-processus)",
                    "type": type(e).__name__,
                    "message": str(e),
                    "traceback": traceback.format_exc(),
                }), 500

            last_stdout = (cp.stdout or "")
            last_stderr = (cp.stderr or "")

            if cp.returncode != 0:
                return jsonify({
                    "error": "scan échouée",
                    "exitCode": cp.returncode,
                    "stderr": (cp.stderr or "")[-4000:],
                    "stdout": (cp.stdout or "")[-4000:],
                }), 500

        try:
            data: Dict[str, Any] = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception as e:
            return jsonify({"error": f"impossible de lire le JSON: {type(e).__name__}: {e}"}), 500

        data.setdefault("scan_id", scan_id)
        data.setdefault("artifacts", {})
        data["artifacts"]["json"] = f"/reports/{scan_id}.json"

        if pdf_path is not None:
            if pdf_path.exists():
                data["artifacts"]["pdf"] = f"/reports/{scan_id}.pdf"
            else:
                # Le PDF était demandé mais n'a pas été produit.
                data.setdefault("pdf_error", {})
                data["pdf_error"] = {
                    "requested": True,
                    "path": str(pdf_path),
                    "message": "PDF demandé mais fichier introuvable après exécution du runner.",
                    "hint": "Regardez stdout/stderr ci-dessous; si vous voyez un UnicodeEncodeError, fixez l'encodage console (PYTHONUTF8=1) ou remplacez les symboles ✓/✗ dans les prints.",
                    "stdout_tail": (last_stdout or "")[-2000:],
                    "stderr_tail": (last_stderr or "")[-2000:],
                }

        if exploit_md_path.exists():
            data["artifacts"]["exploitation_guide"] = f"/reports/{scan_id}_EXPLOITATION_GUIDE.md"

        return jsonify(data)

    @app.get("/reports/<scan_id>.json")
    @require_auth
    def get_report_json(scan_id: str):
        p = reports_dir / f"scan-{scan_id}.json"
        if not p.exists():
            return jsonify({"error": "rapport introuvable"}), 404
        return send_file(str(p), mimetype="application/json")

    @app.get("/reports/<scan_id>.pdf")
    @require_auth
    def get_report_pdf(scan_id: str):
        p = reports_dir / f"scan-{scan_id}.pdf"
        if not p.exists():
            return jsonify({"error": "rapport introuvable"}), 404
        return send_file(str(p), mimetype="application/pdf")

    @app.get("/reports/<scan_id>_EXPLOITATION_GUIDE.md")
    @require_auth
    def get_exploitation_guide(scan_id: str):
        p = reports_dir / f"scan-{scan_id}_EXPLOITATION_GUIDE.md"
        if not p.exists():
            return jsonify({"error": "guide introuvable"}), 404
        return send_file(str(p), mimetype="text/markdown; charset=utf-8")

    return app


if __name__ == "__main__":
    # Local only par défaut (safe). Modifiable via env si besoin.
    host = os.environ.get("A02_API_HOST", "127.0.0.1")
    port = int(os.environ.get("A02_API_PORT", "8000"))
    # Forcer UTF-8 sur Windows pour éviter UnicodeEncodeError (✓ etc.)
    os.environ.setdefault("PYTHONUTF8", "1")
    app = create_app()
    app.run(host=host, port=port, debug=True)
