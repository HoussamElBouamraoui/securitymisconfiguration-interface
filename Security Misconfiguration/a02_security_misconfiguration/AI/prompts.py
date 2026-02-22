def build_pentester_prompt(summary_json: str, *, language: str = "fr") -> str:
    # Output JSON strict pour que le front puisse l'afficher facilement
    return f"""
Tu es un pentesteur senior spécialisé OWASP. Tu dois analyser un rapport de scan A02 (Security Misconfiguration).
Tu dois produire une analyse de qualité professionnelle, avec des idées exploitation active et en restant offensif.

LANGUE: {language}

Contraintes:
- Réponds UNIQUEMENT en JSON (valide).
- Ne mets aucun texte hors JSON.
- Donne des recommandations concrètes et vérifiables.

Format JSON attendu:
{{
  "executive_summary": "string",
  "risk_posture": {{
    "overall_severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL",
    "risk_score_0_100": number,
    "top_3_risks": [ "string", "string", "string" ]
  }},
  "top_findings": [
    {{
      "title": "string",
      "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL",
      "evidence": "string",
      "impact": "string",
      "pentester_view": "string",
      "recommendation": "string",
      "how_to_verify_fix": "string"
    }}
  ],
  "remediation_plan": {{
    "quick_wins_0_1_day": [ "string" ],
    "short_term_1_7_days": [ "string" ],
    "long_term_hardening": [ "string" ]
  }},
  "false_positives_and_limits": [ "string" ],
  "next_manual_checks": [ "string" ]
}}

Voici le résumé structuré du rapport (JSON):
{summary_json}
""".strip()