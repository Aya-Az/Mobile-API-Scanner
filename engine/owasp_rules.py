"""
Règles OWASP Mobile Top 10 & OWASP API Security Top 10
"""

OWASP_MOBILE_TOP10 = [
    {
        "id": "M1",
        "name": "Improper Credential Usage",
        "description": "Utilisation incorrecte des identifiants (hardcoded credentials, stockage non sécurisé)",
        "severity": "CRITICAL",
        "cwe": ["CWE-798", "CWE-312"],
        "tests": ["hardcoded_credentials", "token_in_url", "credentials_in_logs"]
    },
    {
        "id": "M2",
        "name": "Inadequate Supply Chain Security",
        "description": "Sécurité insuffisante de la chaîne d'approvisionnement",
        "severity": "HIGH",
        "cwe": ["CWE-494"],
        "tests": ["outdated_libraries", "vulnerable_dependencies"]
    },
    {
        "id": "M3",
        "name": "Insecure Authentication/Authorization",
        "description": "Authentification et autorisation non sécurisées",
        "severity": "CRITICAL",
        "cwe": ["CWE-287", "CWE-285"],
        "tests": ["broken_auth", "missing_auth", "jwt_weakness", "privilege_escalation"]
    },
    {
        "id": "M4",
        "name": "Insufficient Input/Output Validation",
        "description": "Validation insuffisante des entrées/sorties",
        "severity": "HIGH",
        "cwe": ["CWE-20", "CWE-89", "CWE-79"],
        "tests": ["sql_injection", "xss", "command_injection", "path_traversal"]
    },
    {
        "id": "M5",
        "name": "Insecure Communication",
        "description": "Communications non sécurisées (absence TLS, certificats invalides)",
        "severity": "HIGH",
        "cwe": ["CWE-319", "CWE-295"],
        "tests": ["http_usage", "invalid_ssl", "weak_cipher", "ssl_pinning_bypass"]
    },
    {
        "id": "M6",
        "name": "Inadequate Privacy Controls",
        "description": "Contrôles de confidentialité insuffisants (PII exposée)",
        "severity": "HIGH",
        "cwe": ["CWE-359", "CWE-200"],
        "tests": ["pii_exposure", "data_leakage", "sensitive_data_logging"]
    },
    {
        "id": "M7",
        "name": "Insufficient Binary Protections",
        "description": "Protections binaires insuffisantes (anti-tampering, obfuscation)",
        "severity": "MEDIUM",
        "cwe": ["CWE-656"],
        "tests": ["debug_enabled", "reverse_engineering"]
    },
    {
        "id": "M8",
        "name": "Security Misconfiguration",
        "description": "Mauvaise configuration de sécurité",
        "severity": "MEDIUM",
        "cwe": ["CWE-16"],
        "tests": ["cors_misconfiguration", "debug_endpoints", "verbose_errors", "missing_security_headers"]
    },
    {
        "id": "M9",
        "name": "Insecure Data Storage",
        "description": "Stockage de données non sécurisé",
        "severity": "HIGH",
        "cwe": ["CWE-312", "CWE-921"],
        "tests": ["sensitive_data_storage", "unencrypted_storage"]
    },
    {
        "id": "M10",
        "name": "Insufficient Cryptography",
        "description": "Cryptographie insuffisante (algorithmes faibles, clés courtes)",
        "severity": "HIGH",
        "cwe": ["CWE-326", "CWE-327"],
        "tests": ["weak_jwt_algorithm", "weak_encryption", "hardcoded_keys"]
    }
]

OWASP_API_TOP10 = [
    {
        "id": "API1",
        "name": "Broken Object Level Authorization (BOLA)",
        "description": "Autorisation au niveau objet cassée - accès à des ressources d'autres utilisateurs",
        "severity": "CRITICAL",
        "cwe": ["CWE-639"],
        "tests": ["idor", "object_level_auth"]
    },
    {
        "id": "API2",
        "name": "Broken Authentication",
        "description": "Authentification cassée - mécanismes d'auth défaillants",
        "severity": "CRITICAL",
        "cwe": ["CWE-287"],
        "tests": ["brute_force", "weak_passwords", "token_exposure", "missing_rate_limit"]
    },
    {
        "id": "API3",
        "name": "Broken Object Property Level Authorization",
        "description": "Exposition de propriétés sensibles d'objets",
        "severity": "HIGH",
        "cwe": ["CWE-213"],
        "tests": ["mass_assignment", "excessive_data_exposure"]
    },
    {
        "id": "API4",
        "name": "Unrestricted Resource Consumption",
        "description": "Consommation non limitée de ressources (DoS, rate limiting absent)",
        "severity": "HIGH",
        "cwe": ["CWE-770"],
        "tests": ["rate_limiting", "payload_size", "dos_potential"]
    },
    {
        "id": "API5",
        "name": "Broken Function Level Authorization",
        "description": "Autorisation au niveau fonction cassée - accès à des fonctions admin",
        "severity": "CRITICAL",
        "cwe": ["CWE-285"],
        "tests": ["admin_endpoint_access", "http_method_bypass", "privilege_escalation"]
    },
    {
        "id": "API6",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": "Accès non restreint aux flux métier sensibles",
        "severity": "HIGH",
        "cwe": ["CWE-840"],
        "tests": ["business_logic", "workflow_bypass"]
    },
    {
        "id": "API7",
        "name": "Server Side Request Forgery (SSRF)",
        "description": "Falsification de requêtes côté serveur",
        "severity": "HIGH",
        "cwe": ["CWE-918"],
        "tests": ["ssrf"]
    },
    {
        "id": "API8",
        "name": "Security Misconfiguration",
        "description": "Mauvaise configuration de sécurité API",
        "severity": "MEDIUM",
        "cwe": ["CWE-16"],
        "tests": ["cors", "debug", "security_headers", "verbose_errors"]
    },
    {
        "id": "API9",
        "name": "Improper Inventory Management",
        "description": "Gestion d'inventaire inappropriée - versions API non maintenues",
        "severity": "MEDIUM",
        "cwe": ["CWE-1059"],
        "tests": ["api_versioning", "deprecated_endpoints", "shadow_apis"]
    },
    {
        "id": "API10",
        "name": "Unsafe Consumption of APIs",
        "description": "Consommation non sécurisée d'APIs tierces",
        "severity": "MEDIUM",
        "cwe": ["CWE-346"],
        "tests": ["third_party_trust", "input_validation_third_party"]
    }
]

# Payloads de test pour l'injection
INJECTION_PAYLOADS = {
    "sql": [
        "' OR '1'='1", "'; DROP TABLE users; --", "1 UNION SELECT null--",
        "' OR 1=1--", "admin'--", "1' AND '1'='1", "' OR 'x'='x"
    ],
    "nosql": [
        '{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}',
        '{"$regex": ".*"}', '{"$exists": true}'
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "'><script>alert(1)</script>",
        "<svg onload=alert(1)>"
    ],
    "path_traversal": [
        "../../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2fpasswd", "....//....//etc/passwd"
    ],
    "command_injection": [
        "; ls -la", "| cat /etc/passwd", "`whoami`",
        "$(id)", "; ping -c 1 127.0.0.1"
    ],
    "ssrf": [
        "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22", "file:///etc/passwd",
        "http://[::1]/admin"
    ]
}

# Headers de sécurité requis
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Force HTTPS (HSTS)",
        "severity": "HIGH"
    },
    "X-Content-Type-Options": {
        "description": "Prévient le MIME sniffing",
        "severity": "MEDIUM"
    },
    "X-Frame-Options": {
        "description": "Prévient le clickjacking",
        "severity": "MEDIUM"
    },
    "Content-Security-Policy": {
        "description": "Politique de sécurité du contenu",
        "severity": "HIGH"
    },
    "X-XSS-Protection": {
        "description": "Protection XSS",
        "severity": "MEDIUM"
    },
    "Referrer-Policy": {
        "description": "Politique de référent",
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "description": "Politique des permissions",
        "severity": "LOW"
    }
}

# Headers qui ne devraient PAS être présents
DANGEROUS_HEADERS = {
    "X-Powered-By": "Révèle la technologie utilisée",
    "Server": "Révèle le serveur web et sa version",
    "X-AspNet-Version": "Révèle la version ASP.NET",
    "X-AspNetMvc-Version": "Révèle la version ASP.NET MVC"
}
