"""Run all A02 Security Misconfiguration sub-scans (network + web) and aggregate results."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import time
from typing import Any, Dict, List

try:
    from tqdm import tqdm  # type: ignore
except Exception:  # pragma: no cover
    tqdm = None  # type: ignore

from ..core.base_check import CheckConfig
from ..core.scoring import (
    compute_a02_risk_score,
    derive_scan_severity,
    findings_count_by_severity,
    max_confidence,
    max_severity,
    normalize_confidence,
    normalize_severity,
    severity_counts,
)
from ..registry import all_checks


def _normalize_status(status: str) -> str:
    s = str(status or "COMPLETED").upper()
    if s in {"COMPLETED", "PARTIAL", "ERROR"}:
        return s
    # backward compat
    if s == "COMPLETED" or s == "DONE":
        return "COMPLETED"
    if s == "SKIPPED":
        return "PARTIAL"
    if s == "ERROR" or s == "FAILED":
        return "ERROR"
    return "COMPLETED"


def _error_hint(exc: Exception) -> Dict[str, str]:
    name = type(exc).__name__
    msg = str(exc)
    if "timed out" in msg.lower() or "timeout" in msg.lower():
        return {
            "cause": "Timeout",
            "recommendation": "Augmenter les timeouts (connect/read), vérifier la connectivité réseau, puis relancer le sous-scan.",
        }
    if "name or service not known" in msg.lower() or "dns" in msg.lower():
        return {
            "cause": "DNS/Resolution",
            "recommendation": "Vérifier la résolution DNS et la connectivité, puis relancer.",
        }
    return {
        "cause": name,
        "recommendation": "Vérifier la connectivité/permissions et relancer ce sous-scan. Consulter les logs techniques si nécessaire.",
    }


def _partial_timeout_result(scan_type: str, target: str, timeout_s: float) -> Dict[str, Any]:
    return {
        "scan_type": scan_type,
        "target": target,
        "status": "PARTIAL",
        "severity": "INFO",
        "confidence": "low",
        "findings": [],
        "evidence": "",
        "timestamp": "",
        "metadata": {
            "error": f"TimeoutError: timebox {timeout_s}s exceeded",
            "error_cause": "Timebox",
            "error_recommendation": "Relancer ce sous-scan avec des timeouts plus élevés ou en réduisant la charge (workers).",
        },
    }


def _run_one_check(cls, cfg: CheckConfig, target: str) -> Dict[str, Any]:
    check = cls(cfg)
    try:
        r = check.run(target)
        d = r.to_dict()

        # Strict normalization defaults
        d.setdefault("status", "COMPLETED")
        d["status"] = _normalize_status(d.get("status"))

        d.setdefault("severity", "INFO")
        d["severity"] = normalize_severity(d.get("severity"))

        d.setdefault("confidence", "low")
        d["confidence"] = normalize_confidence(d.get("confidence"))

        d.setdefault("evidence", "")
        d.setdefault("metadata", {})
        d.setdefault("findings", [])

        # Normalize each finding fields (strict model)
        norm_findings = []
        for f in d.get("findings", []) or []:
            nf = {
                "title": f.get("title", ""),
                "severity": normalize_severity(f.get("severity", "INFO")),
                "confidence": normalize_confidence(f.get("confidence", "low")),
                "risk": f.get("risk", f.get("description", "")) or "",
                "evidence": f.get("evidence", ""),
                "recommendation": f.get("recommendation", f.get("remediation", "")) or "",
                "confidence_reason": f.get("confidence_reason")
                or "best-effort detection; manual validation recommended",
            }
            norm_findings.append(nf)
        d["findings"] = norm_findings

        # Enforce scan-level severity/confidence from findings
        if d.get("findings"):
            sev, conf = derive_scan_severity(d["findings"])
            d["severity"] = sev
            d["confidence"] = conf
        else:
            d["severity"] = "INFO"

        return d
    except Exception as e:
        hint = _error_hint(e)
        return {
            "scan_type": getattr(check, "scan_type", cls.__name__),
            "target": target,
            "status": "ERROR",
            "severity": "INFO",
            "confidence": "low",
            "findings": [],
            "evidence": "",
            "timestamp": "",
            "metadata": {
                "error": f"{type(e).__name__}: {e}",
                "error_cause": hint["cause"],
                "error_recommendation": hint["recommendation"],
            },
        }


def _default_workers() -> int:
    cpu = os.cpu_count() or 4
    return max(4, min(16, cpu * 2))


def _format_eta(seconds: float) -> str:
    if seconds <= 0:
        return "0s"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Run full aggressive A02 Security Misconfiguration scan")
    p.add_argument("--target", required=True, help="URL or host/IP")
    p.add_argument("--connect-timeout", type=float, default=3.0)
    p.add_argument("--read-timeout", type=float, default=6.0)
    p.add_argument("--retries", type=int, default=1)
    p.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Nombre de threads (0 = auto). Ex: 4-12 sur machine normale.",
    )
    p.add_argument(
        "--per-scan-timebox",
        type=float,
        default=120.0,
        help="Timebox (secondes) par sous-scan. Si dépassé, statut PARTIAL et le run continue.",
    )
    p.add_argument(
        "--turbo",
        action="store_true",
        help="Mode turbo (non intrusif) : plus de parallélisme + limites adaptées pour éviter les blocages.",
    )
    p.add_argument("--out", default="-", help="Output JSON path or '-' for stdout")
    p.add_argument("--pdf", default="", help="Chemin du rapport PDF à générer (optionnel)")
    p.add_argument("--exploit-guide", default="", help="Chemin du guide d'exploitation MD (optionnel, défaut: même dossier que --out)")
    # Ajout d'une commande pour exécuter des modules spécifiques et afficher l'aide
    p.add_argument("--scan", default="", help="Nom du module à exécuter (ex: port_scanner_aggressive)")
    p.add_argument("--help-scan", action="store_true", help="Liste tous les outils disponibles")
    args = p.parse_args(argv)

    # Base config (valeurs offensives par défaut)
    cfg = CheckConfig(
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        retries=max(0, args.retries),
        per_scan_timeout_seconds=float(args.per_scan_timebox),
    )

    # TURBO tuning (mode ULTRA-OFFENSIF): scan extrêmement agressif
    # Objectif: maximiser la couverture avec détection avancée + exploitation
    if args.turbo:
        cfg.per_scan_timeout_seconds = min(cfg.per_scan_timeout_seconds, 90.0)
        cfg.port_scan_max_ports = 65535  # Scan TOUS les ports
        cfg.port_scan_workers = min(max(cfg.port_scan_workers, 1000), 2000)  # ULTRA agressif
        cfg.web_max_paths = 1000  # MAXIMUM de chemins
        cfg.web_max_requests = 1500  # MAXIMUM de requêtes
        cfg.banner_read_bytes = 8192  # Maximum de données pour l'analyse
        cfg.retries = 3  # Plus de tentatives
        cfg.read_timeout = 10.0  # Plus de temps pour détecter vulnérabilités

    classes = all_checks()
    results: List[Dict[str, Any]] = []

    workers = _default_workers() if int(args.workers) <= 0 else max(1, int(args.workers))
    if args.turbo and int(args.workers) <= 0:
        # Turbo: plus agressif côté perf, mais borné pour ne pas saturer.
        import os as os_module
        cpu = os_module.cpu_count() or 4
        workers = max(workers, min(32, cpu * 4))

    start = time.time()

    # Track ETAs using completed task durations
    completed_durations: List[float] = []

    # Robust timebox implementation: actively monitor all futures with wait()
    # instead of relying on as_completed() which only yields already-done futures.
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        fut_to_scan: Dict[concurrent.futures.Future, str] = {}
        fut_to_start: Dict[concurrent.futures.Future, float] = {}

        for cls in classes:
            f = ex.submit(_run_one_check, cls, cfg, args.target)
            fut_to_scan[f] = getattr(cls, "scan_type", cls.__name__)
            fut_to_start[f] = time.time()

        total = len(fut_to_scan)
        pending = set(fut_to_scan.keys())
        timebox_s = float(cfg.per_scan_timeout_seconds)

        def _on_completed_one():
            if not completed_durations:
                return "?"
            avg = sum(completed_durations) / max(1, len(completed_durations))
            remaining = max(0, total - len(results))
            return _format_eta(avg * remaining)

        if tqdm is not None:
            with tqdm(total=total, desc="A02 scans", unit="check") as bar:
                while pending:
                    # Wait for any future to complete (or timeout check interval)
                    done_now, pending = concurrent.futures.wait(pending, timeout=1.0, return_when=concurrent.futures.FIRST_COMPLETED)

                    # Check for timeboxed futures (still pending but exceeded budget)
                    now = time.time()
                    timedout = {f for f in pending if (now - fut_to_start.get(f, now)) > timebox_s}
                    for f in timedout:
                        scan_type = fut_to_scan.get(f, "unknown")
                        r = _partial_timeout_result(scan_type, args.target, timebox_s)
                        results.append(r)
                        completed_durations.append(timebox_s)
                        bar.update(1)
                        bar.set_postfix({"ETA": _on_completed_one(), "workers": workers, "status": "TIMEBOX"})
                    pending -= timedout

                    # Process completed futures
                    for f in done_now:
                        scan_type = fut_to_scan.get(f, "unknown")
                        t0 = fut_to_start.get(f, time.time())
                        try:
                            r = f.result(timeout=0.01)
                        except Exception as e:
                            hint = _error_hint(e)
                            r = {
                                "scan_type": scan_type,
                                "target": args.target,
                                "status": "ERROR",
                                "severity": "INFO",
                                "confidence": "low",
                                "findings": [],
                                "evidence": "",
                                "timestamp": "",
                                "metadata": {
                                    "error": f"{type(e).__name__}: {e}",
                                    "error_cause": hint["cause"],
                                    "error_recommendation": hint["recommendation"],
                                },
                            }
                        finally:
                            completed_durations.append(max(0.001, time.time() - t0))

                        results.append(r)
                        bar.update(1)
                        bar.set_postfix({"ETA": _on_completed_one(), "workers": workers})
        else:
            # No tqdm: manual progress print
            while pending:
                done_now, pending = concurrent.futures.wait(pending, timeout=1.0, return_when=concurrent.futures.FIRST_COMPLETED)

                now = time.time()
                timedout = {f for f in pending if (now - fut_to_start.get(f, now)) > timebox_s}
                for f in timedout:
                    scan_type = fut_to_scan.get(f, "unknown")
                    r = _partial_timeout_result(scan_type, args.target, timebox_s)
                    results.append(r)
                    completed_durations.append(timebox_s)
                    print(f"[{len(results)}/{total}] {scan_type} TIMEBOX. ETA ~ {_on_completed_one()}")
                pending -= timedout

                for f in done_now:
                    scan_type = fut_to_scan.get(f, "unknown")
                    t0 = fut_to_start.get(f, time.time())
                    try:
                        r = f.result(timeout=0.01)
                    except Exception as e:
                        hint = _error_hint(e)
                        r = {
                            "scan_type": scan_type,
                            "target": args.target,
                            "status": "ERROR",
                            "severity": "INFO",
                            "confidence": "low",
                            "findings": [],
                            "evidence": "",
                            "timestamp": "",
                            "metadata": {
                                "error": f"{type(e).__name__}: {e}",
                                "error_cause": hint["cause"],
                                "error_recommendation": hint["recommendation"],
                            },
                        }
                    finally:
                        completed_durations.append(max(0.001, time.time() - t0))

                    results.append(r)
                    print(f"[{len(results)}/{total}] {scan_type} done. ETA ~ {_on_completed_one()}")

        # Force shutdown remaining threads (cancel pending futures)
        print(f"\n[*] Nettoyage des threads...")
        for f in pending:
            f.cancel()

    finally:
        # Force shutdown with timeout to avoid hanging
        print(f"[*] Arrêt du ThreadPoolExecutor...")
        ex.shutdown(wait=False)  # Don't wait for threads
        print("[OK] Threads arretes")

    duration_s = time.time() - start

    # Summary counts
    scan_counts = severity_counts(results)
    finding_counts = findings_count_by_severity(results)
    total_findings = sum(finding_counts.values())

    overall_sev = max_severity([r.get("severity", "INFO") for r in results])
    overall_conf = max_confidence([r.get("confidence", "low") for r in results])

    # A02 Global Risk Score (explanatory)
    a02_score = compute_a02_risk_score(results)

    # Visual synthesis per sub-scan
    by_scan = []
    for r in sorted(results, key=lambda x: x.get("scan_type", "")):
        fmax = max_severity([f.get("severity", "INFO") for f in (r.get("findings") or [])] or ["INFO"])
        fconf = max_confidence([f.get("confidence", "low") for f in (r.get("findings") or [])] or ["low"])
        by_scan.append(
            {
                "scan_type": r.get("scan_type", ""),
                "findings": len(r.get("findings") or []),
                "max_severity": fmax,
                "confidence": fconf,
                "status": r.get("status", "COMPLETED"),
            }
        )

    aggregated = {
        "target": args.target,
        "status": "COMPLETED",
        "mode": "aggressive" if not args.turbo else "aggressive-turbo",
        "project": "Pentest Assistant",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duration_seconds": round(duration_s, 3),
        "results": results,
        "summary": {
            "total_scans": len(classes),
            "total_findings": total_findings,
            "scans_by_severity": scan_counts,
            "findings_by_severity": finding_counts,
            "overall_severity": overall_sev,
            "overall_confidence": overall_conf,
            "a02_risk_score": a02_score,
            "by_scan": by_scan,
        },
        "metadata": {
            "workers": workers,
            "checks": len(classes),
            "turbo": bool(args.turbo),
            "per_scan_timebox_seconds": float(cfg.per_scan_timeout_seconds),
        },
    }

    # Sauvegarder JSON d'abord (prioritaire)
    payload = json.dumps(aggregated, indent=2, ensure_ascii=False)
    if args.out == "-":
        print(payload)
    else:
        print(f"\n[*] Sauvegarde des résultats JSON...")
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
        print(f"[OK] JSON sauvegarde: {args.out}")

    # Génération PDF (optionnelle, avec timeout)
    if args.pdf:
        print(f"\n[*] Génération du rapport PDF...")
        try:
            from ..reporting.pdf_report import generate_pdf_report

            # Utiliser un timeout pour éviter blocage
            import signal

            def timeout_handler(signum, frame):
                raise TimeoutError("PDF generation timeout")

            # Timeout de 60 secondes pour le PDF
            try:
                if hasattr(signal, 'SIGALRM'):
                    signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(60)

                generate_pdf_report(aggregated, args.pdf)

                if hasattr(signal, 'SIGALRM'):
                    signal.alarm(0)

                aggregated.setdefault("artifacts", {})["pdf_report"] = args.pdf
                print(f"[OK] PDF genere: {args.pdf}")
            except TimeoutError:
                print(f"[!] Timeout lors de la génération PDF (60s)")
                aggregated.setdefault("artifacts", {})["pdf_report_error"] = "Timeout (60s)"

        except Exception as e:
            print(f"[!] Erreur génération PDF: {type(e).__name__}: {e}")
            aggregated.setdefault("artifacts", {})["pdf_report_error"] = f"{type(e).__name__}: {e}"

    print(f"\n[OK] Scan termine en {duration_s:.1f}s")
    print(f"[OK] Findings: {total_findings} ({overall_sev})")
    print(f"[OK] Resultats: {args.out}")

    # Génération du guide d'exploitation (NOUVEAU)
    print(f"\n[*] Génération du guide d'exploitation avec POCs...")
    try:
        from ..reporting.exploitation_generator import (
            generate_exploitation_guide,
            generate_markdown_report
        )

        print(f"[*] Analyse des résultats pour génération POCs...")
        exploitation_guide = generate_exploitation_guide(results)

        # Sauvegarder dans aggregated
        aggregated["exploitation_guide"] = exploitation_guide

        # Générer rapport Markdown avec POCs

        # Déterminer le chemin du fichier d'exploitation
        if args.exploit_guide:
            # Chemin spécifié par l'utilisateur
            exploit_report = args.exploit_guide
        elif args.out != "-":
            # Même dossier que le JSON
            output_dir = os.path.dirname(os.path.abspath(args.out))
            output_basename = os.path.splitext(os.path.basename(args.out))[0]
            exploit_report = os.path.join(output_dir, f"{output_basename}_EXPLOITATION_GUIDE.md")
        else:
            # Dossier courant
            exploit_report = "EXPLOITATION_GUIDE.md"

        print(f"[*] Création du fichier {exploit_report}...")
        generated_file = generate_markdown_report(exploitation_guide, exploit_report)

        # Afficher le chemin absolu pour que l'utilisateur puisse trouver le fichier
        abs_path = os.path.abspath(generated_file)
        print(f"[OK] Guide d'exploitation genere: {abs_path}")
        print(f"[!] Vulnérabilités exploitables: {exploitation_guide['total_vulnerabilities']}")
        print(f"[!] CRITICAL: {exploitation_guide['risk_summary']['CRITICAL']}, HIGH: {exploitation_guide['risk_summary']['HIGH']}")

        # Mettre à jour le JSON avec le guide
        payload_updated = json.dumps(aggregated, indent=2, ensure_ascii=False)
        if args.out != "-":
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(payload_updated)

    except Exception as e:
        print(f"[!] Erreur génération guide exploitation: {type(e).__name__}: {e}")
        import traceback
        print(f"[!] Détails de l'erreur:")
        traceback.print_exc()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
