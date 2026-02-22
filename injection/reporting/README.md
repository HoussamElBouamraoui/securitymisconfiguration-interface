# InjectionHunter — Reporting PDF (style A02)

Ce dossier permet de générer un **rapport PDF** pour `injection/` avec le même rendu que **Security Misconfiguration** (A02), en réutilisant le moteur :
`a02_security_misconfiguration.reporting.pdf_report`.

## Entrées supportées

Le CLI accepte un fichier JSON :
- soit une **liste** de vulnérabilités (dicts),
- soit un **dict** contenant une clé `vulnerabilities`.

Chaque vuln doit au minimum contenir `type` + (optionnel) `param`/`path`/`name`, et idéalement `url`, `payload`, `evidence`.

## Utilisation

```powershell
python -m injection.reporting.cli --in .\vulns.json --out .\report_injection.pdf --target "http://127.0.0.1"
```

## Notes

- Le mapping sévérité/confiance est **heuristique** et peut être affiné.
- Le PDF est généré via ReportLab; il faut que les dépendances du module A02 soient installées (`reportlab`, etc.).
