"""Subdomain wordlists for Module 1 (enumeration) and Module 16 (CDN bypass)."""

# Common subdomains for brute-force (Module 1)
COMMON_SUBS = [
    "www","mail","ftp","localhost","admin","blog","dev","test","staging",
    "api","app","portal","vpn","remote","m","shop","store","cdn","static",
    "img","images","media","assets","secure","login","sso","auth","oauth",
    "dashboard","panel","manage","manager","internal","intranet","git",
    "ci","jenkins","grafana","kibana","elastic","redis","db","mysql",
    "backup","files","download","upload","status","monitor","log","docs",
    "wiki","support","help","info","news","search","mobile","beta","alpha",
]

# Subdomains likely to point to origin IP (Module 16)
ORIGIN_SUBS = [
    "mail","cpanel","webmail","direct","origin","server","ssh",
    "ftp","sftp","ns1","ns2","smtp","pop","imap","api-direct",
    "backend","internal","raw","ip","host","node","real",
    "staging","dev","test","beta","alpha","old","new","backup",
    "direct-connect","no-cdn","nocdn","bare","root",
]
