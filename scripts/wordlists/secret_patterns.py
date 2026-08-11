"""Secret patterns for JS analysis (Module 8) and .git dump (Module 17)."""

SECRET_PATTERNS = [
    # API Keys
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
    (r'ya29\.[0-9A-Za-z\-_]+', 'Google OAuth Token'),
    (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Secret Key'),
    (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Publishable Key'),
    (r'ghp_[0-9a-zA-Z]{36}', 'GitHub PAT'),
    (r'gho_[0-9a-zA-Z]{36}', 'GitHub OAuth Token'),
    (r'github_pat_[0-9A-Za-z_]{82}', 'GitHub Fine-grained PAT'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
    (r'AKIA5N[0-9A-Z]{13}', 'AWS Access Key ID v2'),
    (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT Token'),
    (r'xox[baprs]-[0-9a-zA-Z-]+', 'Slack Token'),
    (r'1\d{9}-[a-zA-Z0-9_-]{24}', 'Firebase URL'),
    (r'[0-9]+/[a-zA-Z0-9_-]{43}', 'Firebase Database Secret'),
    # Generic patterns
    (r'["\']api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'API Key (generic)'),
    (r'["\']secret["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', 'Secret'),
    (r'["\']token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Token (generic)'),
    (r'["\']password["\']?\s*[:=]\s*["\']([^"\']{6,})["\']', 'Password'),
    (r'["\']auth["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Auth Token'),
    (r'Bearer\s+([a-zA-Z0-9_\-.]+)', 'Bearer Token'),
    # Cloud storage
    (r'https://[a-z0-9]+\.s3\.amazonaws\.com', 'S3 Bucket URL'),
    (r'https://[a-z0-9]+\.blob\.core\.windows\.net', 'Azure Blob URL'),
    (r'https://storage\.googleapis\.com/[a-z0-9-]+', 'GCP Storage URL'),
    # Private keys
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'Private Key'),
    # Connection strings
    (r'mongodb(\+srv)?://[^\s"\']+:[^\s"\']+@', 'MongoDB Connection String'),
    (r'postgres://[^\s"\']+:[^\s"\']+@', 'PostgreSQL Connection String'),
    (r'mysql://[^\s"\']+:[^\s"\']+@', 'MySQL Connection String'),
    (r'redis://[^\s"\']+:[^\s"\']+@', 'Redis Connection String'),
]

ENDPOINT_PATTERNS = [
    r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
    r'["\'](/[a-z0-9_-]+/api/[a-z0-9_/-]+)["\']',
    r'["\'](/graphql)["\']',
    r'["\'](/v[0-9]+/[a-z0-9_/-]+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
    r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
    r'XMLHttpRequest.*?open\(["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']',
]
