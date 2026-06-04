"""
Générateur de rapports de vulnérabilités - HTML & JSON
"""

import json
import os
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
from collections import Counter


class ReportGenerator:
    """Génère des rapports de sécurité détaillés"""

    def __init__(self):
        self.reports_dir = Path("reports/output")
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def compile_results(self, scan_id: str, target_url: str,
                        endpoints: List[Dict], vulnerabilities: List[Dict]) -> Dict:
        """Compile les résultats du scan en un objet structuré"""
        severity_counts = Counter(v["severity"] for v in vulnerabilities)
        risk_score = self._calculate_risk_score(vulnerabilities)

        return {
            "scan_id": scan_id,
            "target_url": target_url,
            "scan_date": datetime.now().isoformat(),
            "scanner_version": "1.0.0",
            "endpoints_discovered": len(endpoints),
            "endpoints": endpoints,
            "vulnerabilities": vulnerabilities,
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": {
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "medium": severity_counts.get("MEDIUM", 0),
                "low": severity_counts.get("LOW", 0),
                "info": severity_counts.get("INFO", 0)
            },
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "owasp_coverage": self._get_owasp_coverage(vulnerabilities),
            "recommendations": self._generate_recommendations(vulnerabilities)
        }

    def generate(self, scan_id: str, results: Dict, format: str = "html") -> str:
        """Génère le fichier de rapport"""
        if format == "json":
            return self._generate_json_report(scan_id, results)
        return self._generate_html_report(scan_id, results)

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calcule un score de risque global (0-10)"""
        if not vulnerabilities:
            return 0.0

        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0.1}
        total_weight = sum(weights.get(v["severity"], 0) for v in vulnerabilities)
        max_possible = len(vulnerabilities) * 10

        if max_possible == 0:
            return 0.0

        score = min(10.0, (total_weight / max_possible) * 10 + len(vulnerabilities) * 0.1)
        return round(score, 1)

    def _get_risk_level(self, score: float) -> str:
        if score >= 8: return "CRITIQUE"
        if score >= 6: return "ÉLEVÉ"
        if score >= 4: return "MOYEN"
        if score >= 2: return "FAIBLE"
        return "MINIMAL"

    def _get_owasp_coverage(self, vulnerabilities: List[Dict]) -> Dict:
        """Retourne la couverture OWASP"""
        mobile_covered = set(v["owasp_mobile"] for v in vulnerabilities if v.get("owasp_mobile"))
        api_covered = set(v["owasp_api"] for v in vulnerabilities if v.get("owasp_api"))

        return {
            "mobile_top10_tested": list(mobile_covered),
            "api_top10_tested": list(api_covered),
            "mobile_coverage_percent": round(len(mobile_covered) / 10 * 100, 0),
            "api_coverage_percent": round(len(api_covered) / 10 * 100, 0)
        }

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Génère les recommandations prioritaires"""
        critical_high = [v for v in vulnerabilities if v["severity"] in ["CRITICAL", "HIGH"]]
        seen_recs = set()
        recommendations = []

        for vuln in critical_high[:10]:
            rec = vuln.get("recommendation", "")
            if rec and rec not in seen_recs:
                seen_recs.add(rec)
                recommendations.append({
                    "priority": "IMMÉDIATE" if vuln["severity"] == "CRITICAL" else "HAUTE",
                    "title": vuln["title"],
                    "action": rec,
                    "cwe": vuln.get("cwe", "")
                })

        return recommendations

    def _generate_json_report(self, scan_id: str, results: Dict) -> str:
        """Génère un rapport JSON"""
        path = self.reports_dir / f"report_{scan_id[:8]}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        return str(path)

    def _generate_html_report(self, scan_id: str, results: Dict) -> str:
        """Génère un rapport HTML professionnel"""
        path = self.reports_dir / f"report_{scan_id[:8]}.html"
        html = self._build_html(results)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return str(path)

    def _build_html(self, r: Dict) -> str:
        """Construit le HTML du rapport"""
        vulns = r.get("vulnerabilities", [])

        # ── Palette light (extraite de l'image) ──────────────────────────────
        severity_colors = {
            "CRITICAL": "#ef4444",   # rouge vif
            "HIGH":     "#f97316",   # orange
            "MEDIUM":   "#0ea5e9",   # bleu ciel / teal
            "LOW":      "#22c55e",   # vert
            "INFO":     "#94a3b8"    # gris bleuté
        }
        severity_bg = {
            "CRITICAL": "#fef2f2",
            "HIGH":     "#fff7ed",
            "MEDIUM":   "#f0f9ff",
            "LOW":      "#f0fdf4",
            "INFO":     "#f8fafc"
        }
        risk_colors = {
            "CRITIQUE": "#ef4444",
            "ÉLEVÉ":    "#f97316",
            "MOYEN":    "#0ea5e9",
            "FAIBLE":   "#22c55e",
            "MINIMAL":  "#16a34a"
        }
        # ─────────────────────────────────────────────────────────────────────

        vuln_cards = ""
        for i, v in enumerate(vulns):
            color = severity_colors.get(v["severity"], "#94a3b8")
            bg = severity_bg.get(v["severity"], "#f8fafc")
            vuln_cards += f"""
            <div class="vuln-card" style="border-left: 4px solid {color}; background: {bg};">
                <div class="vuln-header">
                    <span class="severity-badge" style="background:{color}; color:white;">{v['severity']}</span>
                    <span class="vuln-title">{v['title']}</span>
                    <span class="cvss-score">CVSS: {v.get('cvss_score', 'N/A')}</span>
                </div>
                <p class="vuln-desc">{v['description']}</p>
                <div class="vuln-meta">
                    <div><strong> URL:</strong> <code>{v.get('url', 'N/A')}</code></div>
                    <div><strong> Evidence:</strong> <code>{v.get('evidence', 'N/A')}</code></div>
                    <div><strong> OWASP Mobile:</strong> <span class="tag">{v.get('owasp_mobile', 'N/A')}</span>
                         <strong> OWASP API:</strong> <span class="tag">{v.get('owasp_api', 'N/A')}</span>
                         <strong> CWE:</strong> <span class="tag">{v.get('cwe', 'N/A')}</span></div>
                    <div class="recommendation"><strong> Recommandation:</strong> {v.get('recommendation', 'N/A')}</div>
                </div>
            </div>"""

        sev = r.get("severity_breakdown", {})
        recs = r.get("recommendations", [])
        rec_items = "".join(f"""
            <div class="rec-item">
                <span class="rec-priority {'critical' if rec['priority']=='IMMÉDIATE' else 'high'}">{rec['priority']}</span>
                <div><strong>{rec['title']}</strong><p>{rec['action']}</p></div>
            </div>""" for rec in recs[:5])

        risk_color = risk_colors.get(r.get("risk_level", "MOYEN"), "#0ea5e9")

        owasp = r.get("owasp_coverage", {})

        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport de Sécurité - {r['target_url']}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f1f5f9; color: #1e293b; min-height: 100vh; }}
  .header {{ background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); padding: 40px; border-bottom: 1px solid #e2e8f0; box-shadow: 0 1px 4px rgba(0,0,0,.06); }}
  .header h1 {{ font-size: 2rem; color: #0f172a; font-weight: 700; }}
  .header p {{ color: #64748b; margin-top: 8px; }}
  .badge-scanner {{ display: inline-block; background: #2563eb; color: white; padding: 4px 12px; border-radius: 20px; font-size: 12px; margin-bottom: 12px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 20px; }}
  .grid-3 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 30px; }}
  .stat-card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.06); }}
  .stat-card .value {{ font-size: 2.5rem; font-weight: 800; }}
  .stat-card .label {{ color: #64748b; font-size: 14px; margin-top: 4px; }}
  .risk-card {{ background: #ffffff; border: 2px solid {risk_color}; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 30px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }}
  .risk-score {{ font-size: 4rem; font-weight: 900; color: {risk_color}; }}
  .risk-level {{ font-size: 1.5rem; color: {risk_color}; font-weight: 700; }}
  .section {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }}
  .section h2 {{ font-size: 1.2rem; font-weight: 700; margin-bottom: 16px; color: #0f172a; }}
  .vuln-card {{ border-radius: 8px; padding: 16px; margin-bottom: 16px; border: 1px solid #e2e8f0; }}
  .vuln-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }}
  .severity-badge {{ padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 700; white-space: nowrap; }}
  .vuln-title {{ font-weight: 700; font-size: 1rem; color: #0f172a; flex: 1; }}
  .cvss-score {{ font-size: 12px; color: #64748b; font-weight: 600; }}
  .vuln-desc {{ color: #475569; font-size: 14px; margin-bottom: 12px; }}
  .vuln-meta {{ display: flex; flex-direction: column; gap: 6px; font-size: 13px; color: #374151; }}
  .vuln-meta code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; word-break: break-all; color: #1e293b; }}
  .tag {{ background: #e2e8f0; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; color: #1e293b; }}
  .recommendation {{ background: #f0fdf4; padding: 8px 12px; border-radius: 6px; border-left: 3px solid #22c55e; color: #166534; }}
  .progress-bar {{ height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; margin-top: 6px; }}
  .progress-fill {{ height: 100%; background: #2563eb; border-radius: 4px; transition: width 1s; }}
  .rec-item {{ display: flex; gap: 12px; align-items: flex-start; padding: 12px; background: #f8fafc; border-radius: 8px; margin-bottom: 8px; }}
  .rec-priority {{ padding: 4px 10px; border-radius: 10px; font-size: 11px; font-weight: 700; white-space: nowrap; }}
  .rec-priority.critical {{ background: #ef4444; color: white; }}
  .rec-priority.high {{ background: #f97316; color: white; }}
  .rec-item p {{ color: #64748b; font-size: 13px; margin-top: 4px; }}
  .footer {{ text-align: center; color: #94a3b8; padding: 30px; font-size: 13px; }}
  .endpoint-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .endpoint-table th {{ background: #f8fafc; padding: 10px; text-align: left; color: #64748b; font-weight: 600; border-bottom: 1px solid #e2e8f0; }}
  .endpoint-table td {{ padding: 8px 10px; border-top: 1px solid #e2e8f0; color: #475569; }}
  .endpoint-table tr:hover {{ background: #f8fafc; }}
  .status-200 {{ color: #22c55e; }} .status-401 {{ color: #f97316; }} .status-403 {{ color: #ef4444; }}
</style>
</head>
<body>
<div class="header">
  <div style="max-width:1200px; margin:0 auto;">
    <span class="badge-scanner"> Mobile API Security Scanner v1.0</span>
    <h1>Rapport de Vulnérabilités API</h1>
    <p>Cible: <strong>{r['target_url']}</strong> · Scan: {r['scan_date'][:19]} · ID: {r['scan_id'][:8]}</p>
  </div>
</div>

<div class="container">
  <!-- Score de risque -->
  <div class="risk-card">
    <div style="color:#64748b; font-size:14px; margin-bottom:8px;">SCORE DE RISQUE GLOBAL</div>
    <div class="risk-score">{r['risk_score']}/10</div>
    <div class="risk-level">Niveau: {r.get('risk_level', 'N/A')}</div>
  </div>

  <!-- Stats -->
  <div class="grid-3">
    <div class="stat-card"><div class="value" style="color:#ef4444">{sev.get('critical',0)}</div><div class="label"> Critique</div></div>
    <div class="stat-card"><div class="value" style="color:#f97316">{sev.get('high',0)}</div><div class="label"> Élevé</div></div>
    <div class="stat-card"><div class="value" style="color:#0ea5e9">{sev.get('medium',0)}</div><div class="label"> Moyen</div></div>
    <div class="stat-card"><div class="value" style="color:#22c55e">{sev.get('low',0)}</div><div class="label"> Faible</div></div>
    <div class="stat-card"><div class="value" style="color:#2563eb">{r.get('endpoints_discovered',0)}</div><div class="label"> Endpoints</div></div>
    <div class="stat-card"><div class="value" style="color:#8b5cf6">{r.get('total_vulnerabilities',0)}</div><div class="label"> Total vulnérabilités</div></div>
  </div>

  <!-- Couverture OWASP -->
  <div class="section">
    <h2> Couverture OWASP</h2>
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
      <div>
        <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
          <span>OWASP Mobile Top 10</span>
          <strong>{owasp.get('mobile_coverage_percent',0):.0f}%</strong>
        </div>
        <div class="progress-bar"><div class="progress-fill" style="width:{owasp.get('mobile_coverage_percent',0)}%; background:#2563eb;"></div></div>
        <div style="color:#94a3b8; font-size:12px; margin-top:4px;">Testés: {', '.join(owasp.get('mobile_top10_tested', []))}</div>
      </div>
      <div>
        <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
          <span>OWASP API Security Top 10</span>
          <strong>{owasp.get('api_coverage_percent',0):.0f}%</strong>
        </div>
        <div class="progress-bar"><div class="progress-fill" style="width:{owasp.get('api_coverage_percent',0)}%; background:#8b5cf6;"></div></div>
        <div style="color:#94a3b8; font-size:12px; margin-top:4px;">Testés: {', '.join(owasp.get('api_top10_tested', []))}</div>
      </div>
    </div>
  </div>

  <!-- Recommandations -->
  {f'<div class="section"><h2> Recommandations Prioritaires</h2>{rec_items}</div>' if recs else ''}

  <!-- Vulnérabilités -->
  <div class="section">
    <h2> Vulnérabilités Détectées ({r.get('total_vulnerabilities',0)})</h2>
    {vuln_cards if vuln_cards else '<p style="color:#94a3b8; text-align:center; padding:20px;"> Aucune vulnérabilité détectée</p>'}
  </div>

  <!-- Endpoints -->
  <div class="section">
    <h2> Endpoints Découverts ({r.get('endpoints_discovered',0)})</h2>
    <table class="endpoint-table">
      <thead><tr><th>Chemin</th><th>Méthodes</th><th>Status</th><th>Source</th></tr></thead>
      <tbody>
        {''.join(f"""<tr>
          <td><code>{e.get('path','N/A')}</code></td>
          <td>{', '.join(e.get('methods', []))}</td>
          <td class="status-{e.get('status_code','')}">{e.get('status_code','N/A')}</td>
          <td>{e.get('source','N/A')}</td>
        </tr>""" for e in r.get('endpoints', [])[:30])}
      </tbody>
    </table>
  </div>
</div>

<div class="footer">
  <p>Généré par Mobile API Vulnerability Scanner · OWASP Mobile Top 10 & API Security Top 10</p>
  <p>Ce rapport est confidentiel et destiné à des fins de sécurité uniquement.</p>
</div>
</body>
</html>"""