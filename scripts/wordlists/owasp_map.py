"""OWASP Top 10 (2021) mapping and CVSS scores (Module 13)."""

OWASP_2021 = {
    "broken_access_control": "A01:2021 – Broken Access Control",
    "crypto_failures": "A02:2021 – Cryptographic Failures",
    "injection": "A03:2021 – Injection",
    "insecure_design": "A04:2021 – Insecure Design",
    "security_misconfig": "A05:2021 – Security Misconfiguration",
    "vulnerable_components": "A06:2021 – Vulnerable and Outdated Components",
    "auth_failures": "A07:2021 – Identification and Authentication Failures",
    "data_integrity": "A08:2021 – Software and Data Integrity Failures",
    "logging_failures": "A09:2021 – Security Logging and Monitoring Failures",
    "ssrf": "A10:2021 – Server-Side Request Forgery (SSRF)",
}

VULN_OWASP_MAP = {
    "sqli": "injection", "xss": "injection", "nosql": "injection",
    "cmdi": "injection", "ssti": "injection", "ldap_injection": "injection",
    "xpath_injection": "injection", "graphql_injection": "injection",
    "path_traversal": "broken_access_control", "idor": "broken_access_control",
    "ssrf": "ssrf", "open_redirect": "broken_access_control",
    "xxe": "crypto_failures", "sensitive_data": "crypto_failures",
    "missing_headers": "security_misconfig", "cors": "security_misconfig",
    "directory_listing": "security_misconfig",
    "race_condition": "insecure_design",
    "file_upload": "insecure_design",
    "smuggling": "insecure_design",
    "host_header": "insecure_design",
    "weak_tls": "crypto_failures",
    "auth_bypass": "auth_failures", "jwt_weakness": "auth_failures",
    "oauth_misconfig": "auth_failures",
    "default_credentials": "auth_failures",
    "deserialization": "data_integrity",
}

CVSS_SCORES = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
