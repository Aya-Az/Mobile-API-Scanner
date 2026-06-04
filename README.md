
#  Mobile API Vulnerability Scanner

##  Description du projet

Le **Mobile API Vulnerability Scanner** est un outil automatisé d'analyse de sécurité conçu spécifiquement pour les APIs mobiles. Il permet de détecter les vulnérabilités critiques conformément aux standards OWASP et génère des rapports détaillés pour faciliter la correction des failles.

###  Objectifs pédagogiques

- Comprendre les enjeux de la sécurité des APIs mobiles
- Appliquer les bonnes pratiques OWASP Mobile Top 10
- Maîtriser les tests de sécurité automatisés
- Générer des rapports de vulnérabilités exploitables

---

## 🏗️ Architecture du projet

```
┌─────────────────────────────────────────────────────────────────┐
│                         FastAPI Server                          │
│                      (http://localhost:8000)                    │
└─────────────────────────────────────────────────────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   APIScanner    │────▶│ VulnerabilityEngine  │────▶│ ReportGenerator │
│                 │     │                      │     │                 │
│ • Découverte    │     │ • M1-M10 Mobile      │     │ • HTML rapport  │
│ • OpenAPI/Spec  │     │ • API1-API10         │     │ • JSON export   │
│ • Bruteforce    │     │ • Tests injection    │     │ • Statistiques  │
│ • Endpoints     │     │ • IDOR/BOLA          │     │ • Recommandations│
└─────────────────┘     └──────────────────────┘     └─────────────────┘
```

## 🚀 Installation et démarrage

### 1. Cloner le projet

```bash
git clone https://github.com/votre-repo/mobile-api-scanner.git
cd mobile-api-scanner
```

### 2. Lancer l'application

#### Windows
```cmd
start.bat
```

#### Linux / macOS
```bash
chmod +x start.sh
./start.sh
```

### 3. Accéder à l'interface

| URL                        | Description                    |
|----------------------------|--------------------------------|
| http://localhost:8000      | Interface web principale       |
| http://localhost:8000/docs | Documentation API (Swagger UI) |

---

##  Utilisation

### Via l'interface web

1. Saisissez l'URL de l'API à tester (ex: `https://api.example.com`)
2. Sélectionnez le niveau d'analyse :
   - **Mode passif** : Lecture seule, sans envoi de payloads
   - **Mode actif** (recommandé) : Tests complets
   - **Mode agressif** : Tests exhaustifs (plus long)
3. Cochez les tests à effectuer
4. Cliquez sur **"Lancer l'analyse"**
5. Consultez les résultats et téléchargez le rapport

### Via l'API REST

#### Démarrer un scan

```bash
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://httpbin.org",
    "options": {
      "scan_level": "active",
      "check_ssl": true,
      "check_injection": true,
      "check_auth": true
    }
  }'
```

#### Vérifier le statut

```bash
curl "http://localhost:8000/api/scan/{scan_id}/status"
```

#### Récupérer les résultats

```bash
curl "http://localhost:8000/api/scan/{scan_id}/results"
```

#### Télécharger le rapport

```bash
# Rapport HTML
curl "http://localhost:8000/api/scan/{scan_id}/report?format=html" --output rapport.html

# Rapport JSON
curl "http://localhost:8000/api/scan/{scan_id}/report?format=json" --output rapport.json
```

#### Lister tous les scans

```bash
curl "http://localhost:8000/api/scans"
```

---

##  Tests de vulnérabilités implémentés

### OWASP Mobile Top 10

| ID | Vulnérabilité                   | Description                             |
|----|---------------------------------|-----------------------------------------|
| M1 | Improper Credential Usage       | Identifiants codés en dur, JWT alg:none |
| M2 | Inadequate Supply Chain         | Bibliothèques vulnérables               |
| M3 | Insecure Authentication         | Bypass auth, JWT faible                 |
| M4 | Insufficient Input Validation   | SQL, NoSQL, XSS, Path Traversal         |
| M5 | Insecure Communication          | HTTP, SSL invalide                      |
| M6 | Inadequate Privacy Controls     | Exposition de données sensibles         |
| M7 | Insufficient Binary Protections | Endpoints debug                         |
| M8 | Security Misconfiguration       | Headers manquants, CORS                 |
| M9 | Insecure Data Storage           | Données exposées sans auth              |
| M10 | Insufficient Cryptography      | Algorithmes faibles                     |

### OWASP API Top 10

| ID   | Vulnérabilité                       | Description                     |
|------|-------------------------------------|---------------------------------|
| API1 | Broken Object Level Authorization   | IDOR / BOLA                     |
| API2 | Broken Authentication               | Rate limiting absent            |
| API3 | Excessive Data Exposure             | Données sensibles dans réponses |
| API4 | Lack of Rate Limiting               | Attaques par déni de service    |
| API5 | Broken Function Level Authorization | Endpoints admin accessibles     |
| API6 | Unrestricted Access                 | Contournement workflow          |
| API7 | Server Side Request Forgery         | SSRF (désactivé par défaut)     |
| API8 | Security Misconfiguration           | CORS, headers sécurité          |
| API9 | Improper Inventory Management       | Versions API dépréciées         |
| API10| Unsafe API Consumption              | Confiance tierce parties        |

---

##  Structure du projet

```
mobile-api-scanner/
│
├── main.py                 # Point d'entrée FastAPI
├── models.py               # Modèles Pydantic
├── requirements.txt        # Dépendances Python
├── start.bat              # Script démarrage Windows
├── start.sh               # Script démarrage Linux/Mac
│
├── scanner/
│   ├── __init__.py
│   └── api_scanner.py     # Découverte des endpoints
│
├── engine/
│   ├── __init__.py
│   ├── vulnerability_engine.py  # Moteur de tests
│   └── owasp_rules.py           # Règles OWASP
│
├── reports/
│   ├── __init__.py
│   ├── report_generator.py       # Génération rapports
│   └── output/                   # Rapports générés
│
├── templates/
│   └── index.html         # Interface web
│

```

---

##  Exemple de rapport généré

### Rapport HTML
- Score de risque global (/10)
- Répartition par sévérité (Critique, Élevé, Moyen, Faible)
- Couverture OWASP (Mobile et API)
- Liste détaillée des vulnérabilités
- Recommandations priorisées
- Endpoints découverts

### Rapport JSON
Structure exploitable pour intégration CI/CD :
```json
{
  "scan_id": "uuid",
  "target_url": "https://api.example.com",
  "risk_score": 7.2,
  "risk_level": "ÉLEVÉ",
  "vulnerabilities": [...],
  "severity_breakdown": {...},
  "recommendations": [...]
}
```

---

##  Configuration avancée

### Options de scan

| Option          | Type   | Défaut   | Description                     |
|-----------------|--------|----------|---------------------------------|
| `scan_level`    | string | `active` | passive / active / aggressive   |
| `timeout`       | int    | 10       | Timeout des requêtes (secondes) |
| `max_endpoints` | int    | 50       | Nombre max d'endpoints à tester |
| `auth_token`    | string | null     | Token d'authentification Bearer |
| `api_key`       | string | null     | Clé API                         |
| `custom_headers`| object | {}       | Headers personnalisés           |

### Variables d'environnement

```bash
# Désactiver la vérification SSL (tests uniquement)
export PYTHONHTTPSVERIFY=0
```

---

##  Tests de démonstration

Vous pouvez tester le scanner sur ces APIs publiques :

| URL                                    | Description         |
|----------------------------------------|---------------------|
| https://httpbin.org                    |API de test HTTP     |
| https://jsonplaceholder.typicode.com   | API factice REST    |
| https://reqres.in                      | API de test         |
| https://api.restful-api.dev            | API de démonstration|

---

##  Améliorations possibles

| Priorité| Fonctionnalité                            |
|---------|-------------------------------------------|
| Haute   | Persistance des scans (SQLite/PostgreSQL) |
| Haute   | Authentification OAuth2 / JWT             |
| Moyenne | Intégration OWASP ZAP                     |
| Moyenne | Export Postman collection                 |
| Basse   | Tests unitaires avec pytest               |
| Basse   | Conteneurisation Docker                   |



##  Références

- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)