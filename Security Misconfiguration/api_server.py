"""
API locale pour relier l'interface web (Vite/React) au scanner A02.

Objectif:
- Exposer un endpoint HTTP simple /scan qui exécute le runner existant et renvoie du JSON.
- Optionnel: générer un PDF et le servir.

Conçu pour un usage local (127.0.0.1) et une intégration UI.
"""

from __future__ import annotations

import json
import bcrypt
import os
import subprocess
import tempfile
import traceback
import uuid
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional
from functools import wraps

import jwt
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from a02_security_misconfiguration.database.db import db, migrate
from a02_security_misconfiguration.database.models import User, ScanRun, Finding, Artifact, AuditLog

# Les runners sont exécutés via subprocess (ne pas importer main() ici)
from a02_security_misconfiguration.registry import CHECKS

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(pw: str, pw_hash: str) -> bool:
    return bcrypt.checkpw(pw.encode("utf-8"), pw_hash.encode("utf-8"))

OLLAMA_BASE = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "deepseek-r1:8b")

def clean_ai_response(text: str) -> str:
    """Nettoie la réponse de l'IA pour supprimer le markdown et les caractères problématiques."""
    import re

    # 1. Supprimer tous les ** et __ (markdown bold/italic)
    text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)  # **texte** -> texte
    text = re.sub(r'__([^_]+)__', r'\1', text)      # __texte__ -> texte
    text = re.sub(r'\*\*', '', text)                # ** restants
    text = re.sub(r'__', '', text)                  # __ restants
    text = re.sub(r'\*([^*\n]+)\*', r'\1', text)    # *texte* -> texte

    # 2. Supprimer les titres markdown # mais garder le texte
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)

    # 3. Supprimer les caractères unicode bizarres (chinois, emojis, etc.)
    # Garde: ASCII de base + caractères français/européens + cyrillique
    text = re.sub(r'[^\x00-\x7F\u00C0-\u024F\u0400-\u04FF\n\r\t]', '', text)

    # 4. Nettoyer les espaces multiples (mais garder les retours à la ligne)
    text = re.sub(r' +', ' ', text)
    text = re.sub(r'\n\n\n+', '\n\n', text)

    # 5. Nettoyer les lignes vides au début/fin
    text = text.strip()

    return text

def ollama_generate_text(prompt: str, *, temperature: float = 0.2, max_tokens: int = 900) -> str:
    r = requests.post(
        f"{OLLAMA_BASE}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        },
        timeout=300,
    )
    r.raise_for_status()
    response = r.json().get("response", "")
    return clean_ai_response(response)

def summarize_report_for_llm(report: dict, max_findings: int = 30) -> str:
    scan_id = report.get("scan_id") or report.get("scanId") or ""
    target = report.get("target") or ""
    risk = report.get("riskScore") or report.get("risk_score") or ""
    overall = report.get("overallSeverity") or report.get("overall_severity") or ""

    results = report.get("results") or []
    items = []
    for mod in results:
        mod_name = mod.get("moduleName") or mod.get("moduleId") or "module"
        sev = (mod.get("severity") or "info").upper()
        for f in (mod.get("findings") or [])[:10]:
            title = f.get("title") or f.get("name") or f.get("rule") or "Finding"
            evidence = f.get("evidence") or f.get("details") or ""
            if not isinstance(evidence, str):
                evidence = str(evidence)
            evidence = evidence[:300]
            rec = f.get("recommendation") or f.get("fix") or ""
            if not isinstance(rec, str):
                rec = str(rec)
            rec = rec[:220]
            items.append(f"- [{sev}] {mod_name}: {title}\n  evidence: {evidence}\n  fix: {rec}")
            if len(items) >= max_findings:
                break
        if len(items) >= max_findings:
            break

    header = f"scan_id={scan_id}\ntarget={target}\nriskScore={risk}\noverallSeverity={overall}\n"
    return header + "\n".join(items)

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


def generate_token(user_id: int, role: str) -> str:
    payload = {
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES),
        "type": "access_token",
        "user_id": user_id,
        "role": role,
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
                "hint": "Obtenez un token via GET /auth/token",
            }), 401

        token = auth_header[7:]  # Enlever "Bearer "
        payload = verify_token(token)
        if payload is None:
            return jsonify({
                "error": "Token invalide ou expiré",
                "message": "Le token JWT n'est pas valide ou a expiré",
            }), 401

        request.jwt_payload = payload
        request.user_id = payload.get("user_id")
        request.user_role = payload.get("role")
        return f(*args, **kwargs)

    return decorated_function


def get_or_create_system_user_id() -> int:
    """Retourne l'ID du user 'system'. Le crée si absent."""
    u = User.query.filter_by(username="system").first()
    if u:
        return u.id
    u = User(email="system@local", username="system", password_hash="x", role="admin")
    db.session.add(u)
    db.session.commit()
    return u.id


def log_action(user_id: int | None, scan_db_id: int | None, action: str, details: dict):
    """Écrit un audit log."""
    db.session.add(AuditLog(
        user_id=user_id,
        scan_id=scan_db_id,
        action=action,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
        details=json.dumps(details, ensure_ascii=False),
    ))
    db.session.commit()


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    # SQLite -> instance/a02_scans.db
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///a02_scans.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"check_same_thread": False}}

    db.init_app(app)
    migrate.init_app(app, db)

    CORS(app, resources={r"/*": {"origins": "*"}})

    import sys
    python_exe = sys.executable

    reports_dir = Path(tempfile.gettempdir()) / "a02_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)



    @app.get("/auth/token")
    def get_token():
        """Endpoint public pour obtenir un token JWT (accès local seulement recommandé)."""
        system = User.query.filter_by(username="system").first()
        if not system:
            system = User(email="system@local", username="system", password_hash=hash_password("system"), role="admin")
            db.session.add(system)
            db.session.commit()

        token = generate_token(user_id=system.id, role=system.role)
        return jsonify({
            "token": token,
            "type": "Bearer",
            "expiresIn": TOKEN_EXPIRATION_MINUTES * 60,
            "message": "Utilisez ce token dans le header 'Authorization: Bearer <token>' pour les appels suivants",
        })

    @app.post("/auth/register")
    def register():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""

        if not email or not username or not password:
            return jsonify({"error": "email, username, password requis"}), 400

        if User.query.filter((User.email == email) | (User.username == username)).first():
            return jsonify({"error": "email ou username déjà utilisé"}), 409

        u = User(
            email=email,
            username=username,
            password_hash=hash_password(password),
            role="user",
        )
        db.session.add(u)
        db.session.commit()

        token = generate_token(user_id=u.id, role=u.role)
        return jsonify({"token": token, "type": "Bearer", "expiresIn": TOKEN_EXPIRATION_MINUTES * 60})

    @app.post("/auth/login")
    def login():
        payload = request.get_json(silent=True) or {}
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""

        if not username or not password:
            return jsonify({"error": "username et password requis"}), 400

        u = User.query.filter_by(username=username).first()
        if not u:
            return jsonify({"error": "identifiants invalides"}), 401

        # ⚠️ si tu avais des users de test avec password_hash="x"
        try:
            ok = check_password(password, u.password_hash)
        except Exception:
            ok = False

        if not ok:
            return jsonify({"error": "identifiants invalides"}), 401

        token = generate_token(user_id=u.id, role=u.role)
        return jsonify({"token": token, "type": "Bearer", "expiresIn": TOKEN_EXPIRATION_MINUTES * 60})

    @app.post("/auth/renew")
    @require_auth
    def renew_token():
        """Endpoint sécurisé pour renouveler un token (avec token valide)."""
        user_id = request.jwt_payload.get("user_id")
        role = request.jwt_payload.get("role", "user")
        new_token = generate_token(user_id=user_id, role=role)
        return jsonify({
            "token": new_token,
            "type": "Bearer",
            "expiresIn": TOKEN_EXPIRATION_MINUTES * 60,
        })

    @app.get("/auth/me")
    @require_auth
    def me():
        """Endpoint de diagnostic : affiche l'utilisateur connecté et les infos du token."""
        return jsonify({
            "user_id": request.user_id,
            "role": request.user_role,
            "payload": request.jwt_payload,
        })

    @app.get("/health")
    def health():
        """Endpoint health check (pas d'authentification requise)."""
        return jsonify({"status": "ok", "version": "1.0.0"})

    @app.get("/scans")
    @require_auth
    def scans():
        return jsonify({
            "count": len(CHECKS),
            "scans": sorted(CHECKS.keys()),
        })

    # ✅ Historique DB pour le frontend
    @app.get("/api/history")
    @require_auth
    def history():
        items = ScanRun.query.order_by(ScanRun.started_at.desc()).limit(50).all()
        return jsonify([
            {
                "id": s.id,
                "target": s.target,
                "scan_type": s.scan_type,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in items
        ])



    @app.post("/scan")
    @require_auth
    def scan():
        payload = request.get_json(silent=True) or {}
        target = (payload.get("target") or "").strip()
        if not target:
            return jsonify({"error": "target requis"}), 400

        # --- Option UI: exécuter un module seul (ou une liste de modules).
        scan_name = (payload.get("scan") or "").strip()
        scans_list = payload.get("scans")
        if not scan_name and isinstance(scans_list, list) and scans_list:
            scan_name = str(scans_list[0]).strip()

        connect_timeout = _safe_float(payload.get("connectTimeout"), 3.0)
        read_timeout = _safe_float(payload.get("readTimeout"), 6.0)
        retries = _safe_int(payload.get("retries"), 1)
        workers = _safe_int(payload.get("workers"), 0)
        per_scan_timebox = _safe_float(payload.get("perScanTimebox"), 300.0)
        turbo = bool(payload.get("turbo", False))
        generate_pdf = bool(payload.get("generatePdf", False))

        # --- DB: créer un scan RUNNING ---
        user_id = request.user_id
        if not user_id:
            return jsonify({"error": "Token invalide: user_id manquant"}), 401

        scan_db = ScanRun(
            user_id=user_id,
            target=target,
            scan_type=("A02" if not scan_name else f"A02:{scan_name}"),
            status="RUNNING",
            parameters_json=json.dumps(payload, ensure_ascii=False),
        )
        db.session.add(scan_db)
        db.session.commit()

        log_action(user_id, scan_db.id, "SCAN_START", {"target": target, "scan": scan_name or "full"})

        def fail(status_code: int, message: str, extra: dict):
            scan_db.status = "ERROR"
            scan_db.finished_at = datetime.utcnow()
            scan_db.error_message = message
            db.session.commit()
            log_action(user_id, scan_db.id, "SCAN_FAILED", {"message": message, **extra})
            return jsonify({"error": message, **extra}), status_code

        # --- Fichiers de report (uuid côté fichiers)
        scan_uuid = str(uuid.uuid4())
        json_path = reports_dir / f"scan-{scan_uuid}.json"
        pdf_path: Optional[Path] = (reports_dir / f"scan-{scan_uuid}.pdf") if generate_pdf else None
        exploit_md_path = reports_dir / f"scan-{scan_uuid}_EXPLOITATION_GUIDE.md"

        last_stdout = ""
        last_stderr = ""

        if scan_name:
            if scan_name not in CHECKS:
                return fail(400, "scan inconnu", {
                    "scan": scan_name,
                    "availableScans": sorted(CHECKS.keys()),
                })

            single_tmp = reports_dir / f"scan-{scan_uuid}_single.json"
            argv = [
                "--target", target,
                "--connect-timeout", str(connect_timeout),
                "--read-timeout", str(read_timeout),
                "--retries", str(retries),
                "--per-scan-timebox", str(per_scan_timebox),
                "--scan", scan_name,
                "--out", str(single_tmp),
            ]

            cmd = [python_exe, "-m", "a02_security_misconfiguration.runner.run_single", *argv]

            try:
                cp = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=max(30.0, float(per_scan_timebox) + 20.0),
                )
            except Exception as e:
                return fail(500, "exception pendant l'exécution du sous-processus", {
                    "scan": scan_name,
                    "type": type(e).__name__,
                    "message": str(e),
                    "traceback": traceback.format_exc(),
                })

            last_stdout = (cp.stdout or "")
            last_stderr = (cp.stderr or "")

            if cp.returncode != 0:
                return fail(500, "scan échouée", {
                    "exitCode": cp.returncode,
                    "scan": scan_name,
                    "stderr": (cp.stderr or "")[-4000:],
                    "stdout": (cp.stdout or "")[-4000:],
                })

            try:
                single_data: Dict[str, Any] = json.loads(single_tmp.read_text(encoding="utf-8"))
            except Exception as e:
                return fail(500, "impossible de lire le JSON (single)", {
                    "type": type(e).__name__,
                    "message": str(e),
                })

            data: Dict[str, Any] = {
                "scan_id": scan_uuid,
                "target": target,
                "status": single_data.get("status", "COMPLETED"),
                "mode": "single",
                "results": [single_data],
                "artifacts": {"json": f"/reports/{scan_uuid}.json"},
            }
            json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

        else:
            argv = [
                "--target", target,
                "--connect-timeout", str(connect_timeout),
                "--read-timeout", str(read_timeout),
                "--retries", str(retries),
                "--per-scan-timebox", str(per_scan_timebox),
                "--out", str(json_path),
            ]
            if workers:
                argv += ["--workers", str(workers)]
            if turbo:
                argv += ["--turbo"]
            if pdf_path is not None:
                argv += ["--pdf", str(pdf_path)]
            argv += ["--exploit-guide", str(exploit_md_path)]

            cmd = [python_exe, "-m", "a02_security_misconfiguration.runner.run_full_aggressive", *argv]

            try:
                cp = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=max(60.0, float(per_scan_timebox) * 2 + 60.0),
                )
            except Exception as e:
                return fail(500, "exception pendant l'exécution du scan complet (sous-processus)", {
                    "type": type(e).__name__,
                    "message": str(e),
                    "traceback": traceback.format_exc(),
                })

            last_stdout = (cp.stdout or "")
            last_stderr = (cp.stderr or "")

            if cp.returncode != 0:
                return fail(500, "scan échouée", {
                    "exitCode": cp.returncode,
                    "stderr": (cp.stderr or "")[-4000:],
                    "stdout": (cp.stdout or "")[-4000:],
                })

        try:
            data: Dict[str, Any] = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception as e:
            return fail(500, "impossible de lire le JSON (final)", {
                "type": type(e).__name__,
                "message": str(e),
            })

        data.setdefault("scan_id", scan_uuid)
        data.setdefault("artifacts", {})
        data["artifacts"]["json"] = f"/reports/{scan_uuid}.json"

        if pdf_path is not None:
            if pdf_path.exists():
                data["artifacts"]["pdf"] = f"/reports/{scan_uuid}.pdf"
            else:
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
            data["artifacts"]["exploitation_guide"] = f"/reports/{scan_uuid}_EXPLOITATION_GUIDE.md"

        # --- DB: finaliser scan DONE + artifacts + logs ---
        scan_db.status = "DONE"
        scan_db.finished_at = datetime.utcnow()
        scan_db.summary_json = json.dumps({
            "scan_uuid": data.get("scan_id"),
            "mode": data.get("mode"),
            "status": data.get("status"),
            "results_count": len(data.get("results", [])),
        }, ensure_ascii=False)

        arts = data.get("artifacts", {}) or {}
        if arts.get("json"):
            db.session.add(Artifact(scan_id=scan_db.id, type="json", path=arts["json"]))
        if arts.get("pdf"):
            db.session.add(Artifact(scan_id=scan_db.id, type="pdf", path=arts["pdf"]))
        if arts.get("exploitation_guide"):
            db.session.add(Artifact(scan_id=scan_db.id, type="md", path=arts["exploitation_guide"]))

        db.session.commit()
        log_action(user_id, scan_db.id, "SCAN_DONE", {"scan_uuid": data.get("scan_id")})

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

    @app.post("/ai/chat")
    @require_auth
    def ai_chat():
        """Endpoint pour dialoguer avec l'IA (analyse rapport ou question ouverte)."""
        payload = request.get_json(silent=True) or {}
        mode = payload.get("mode", "ask")  # "ask" ou "report"
        scan_id = payload.get("scan_id")
        question = payload.get("question", "")
        language = payload.get("language", "fr")
        depth = payload.get("depth", "normal")  # normal ou deep

        if mode == "report":
            # Analyse d'un rapport de scan
            if not scan_id:
                return jsonify({"error": "scan_id requis pour mode=report"}), 400

            # Charger le rapport JSON
            json_path = reports_dir / f"scan-{scan_id}.json"
            if not json_path.exists():
                return jsonify({"error": f"Rapport {scan_id} introuvable"}), 404

            try:
                report_data = json.loads(json_path.read_text(encoding="utf-8"))
            except Exception as e:
                return jsonify({"error": f"Impossible de lire le rapport: {e}"}), 500

            # Résumer le rapport pour le LLM
            summary = summarize_report_for_llm(report_data, max_findings=50 if depth == "deep" else 30)

            prompt = f"""Tu es un expert en cybersécurité. Analyse ce rapport de scan OWASP A02 (Security Misconfiguration).

Rapport:
{summary}

IMPORTANT: Réponds en TEXTE BRUT UNIQUEMENT (pas de markdown, pas de **, pas de #, pas de symboles spéciaux).

Instructions:
- Langue: {language}
- Résumé exécutif: 2-3 phrases
- Liste des vulnérabilités CRITIQUES avec impacts
- Recommandations prioritaires (quick wins)
- Format: retours à la ligne + listes à puces simples (- item)
- Mets les concepts clés en MAJUSCULES (exemple: OWASP, TLS, CORS)
- Pas de markdown, pas de gras, pas de symboles fantaisie
- Sois concis et précis

Analyse (texte brut):"""

            try:
                answer = ollama_generate_text(prompt, temperature=0.3, max_tokens=1200)
                log_action(request.user_id, None, "AI_ANALYZE_REPORT", {"scan_id": scan_id, "depth": depth})
                return jsonify({"answer": answer.strip(), "mode": "report", "scan_id": scan_id})
            except Exception as e:
                return jsonify({"error": f"Erreur IA: {e}"}), 500

        elif mode == "ask":
            # Question ouverte (avec contexte optionnel du scan)
            if not question:
                return jsonify({"error": "question requise pour mode=ask"}), 400

            context = ""
            if scan_id:
                json_path = reports_dir / f"scan-{scan_id}.json"
                if json_path.exists():
                    try:
                        report_data = json.loads(json_path.read_text(encoding="utf-8"))
                        context = f"\n\nContexte du dernier scan:\n{summarize_report_for_llm(report_data, max_findings=15)}"
                    except Exception:
                        pass

            prompt = f"""Tu es un assistant expert en cybersécurité et pentesting.

Question: {question}{context}

IMPORTANT: Réponds en TEXTE BRUT UNIQUEMENT (pas de markdown, pas de **, pas de #, pas de symboles spéciaux).

Règles:
- Langue: {language}
- Si question hors cybersécurité: réponds "Désolé, je suis spécialisé en sécurité informatique uniquement"
- Structure: retours à la ligne + listes à puces simples (- item)
- Mets les concepts clés en MAJUSCULES (exemple: OWASP, SQL, XSS)
- Format: texte simple, clair, technique
- Pas de markdown, pas de gras, pas de symboles fantaisie

Réponse (texte brut):"""

            try:
                answer = ollama_generate_text(prompt, temperature=0.4, max_tokens=800)
                log_action(request.user_id, None, "AI_ASK", {"question": question[:200], "has_context": bool(context)})
                return jsonify({"answer": answer.strip(), "mode": "ask"})
            except Exception as e:
                return jsonify({"error": f"Erreur IA: {e}"}), 500

        else:
            return jsonify({"error": f"mode inconnu: {mode}"}), 400

    return app


if __name__ == "__main__":
    host = os.environ.get("A02_API_HOST", "127.0.0.1")
    port = int(os.environ.get("A02_API_PORT", "8000"))
    os.environ.setdefault("PYTHONUTF8", "1")
    app = create_app()
    app.run(host=host, port=port, debug=True)