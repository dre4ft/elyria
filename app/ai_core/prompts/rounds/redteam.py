# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Red Team round templates — exploration prompts for iterative pentesting.
"""

# Distribution: ~40/20/40% (bash/quick/http), 30 slots
DISTRIBUTION = [
    "BASH", "HTTP", "QUICK", "HTTP", "BASH", "HTTP", "BASH", "HTTP",
    "QUICK", "HTTP", "BASH", "HTTP", "HTTP", "QUICK", "HTTP",
    "BASH", "HTTP", "QUICK", "HTTP", "BASH", "HTTP", "BASH", "HTTP",
    "QUICK", "HTTP", "BASH", "HTTP", "HTTP", "QUICK", "HTTP",
]

BASH_ROUNDS = [
    "BASH RECON: Call bash: ['nmap -sV -p 80,443,8080,8443,3000,5000,8000,9000 --open TARGET', 'curl -s -I https://TARGET', 'curl -s https://TARGET/robots.txt', 'curl -s https://TARGET/.well-known/security.txt', 'dig TARGET A +short']. Then 8 GET requests to /api, /admin, /docs, /graphql, /swagger, /.well-known/jwks.json, /api/v1, /api/health.",
    "BASH JWT + INJECTION: Call bash: ['curl -s https://TARGET/.well-known/jwks.json | jq .', 'python3 -c \"import jwt,base64,sys; parts=sys.stdin.read().strip().split('.'); print(base64.urlsafe_b64decode(parts[1]+'==').decode())\" <<< YOUR_JWT', 'curl -s \"https://TARGET/api/users?id=1 OR 1=1--\"', 'curl -s \"https://TARGET/api/users?id=1' UNION SELECT 1,2,3--\"']. Then 8 SQLi/XSS payload requests.",
    "BASH DEEP RECON: Call bash: ['curl -s https://crt.sh/?q=%25.TARGET_DOMAIN&output=json | python3 -c \"import sys,json; [print(c['name_value']) for c in json.load(sys.stdin)[:30]]\"', 'dig TARGET_DOMAIN MX TXT NS +short', 'curl -s https://TARGET/sitemap.xml | head -30', 'ffuf -u TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -timeout 5 -s | head -15']. Then 8 requests to newly discovered paths.",
]

QUICK_ROUNDS = [
    "SCAN + HTTP: pentest_quick_nuclei on TARGET. Then 10 GET requests probing .env, /actuator, /actuator/health, /debug, /console, /swagger-ui.html, /api-docs, /graphiql, /metrics, /status.",
    "FUZZ + SQLI: pentest_quick_ffuf with url TARGET/api/FUZZ. pentest_quick_sqli on the 3 most promising endpoints. Then 8 requests to ffuf-discovered paths.",
    "NMAP + HTTP: pentest_quick_nmap. Then 10 requests to any new ports discovered. Also retest all known endpoints with PUT, DELETE, PATCH methods.",
]

# HTTP rounds are DYNAMIC — they depend on collection_requests and auth_type.
# Use build_http_rounds() to generate them.

def build_http_rounds(target: str, collection_paths: list = None, auth_type: str = "jwt_bearer") -> list:
    """Build HTTP round templates based on available context."""

    known_endpoints = "/api/users, /api/login, /api/me, /api/products, /api/orders, /api/admin/stats, /api/wallet, /api/health, /api/config"
    if collection_paths:
        sample = [p.replace(target, "") for p in collection_paths[:15]]
        known_endpoints = ", ".join(sample)

    auth_templates = {
        "jwt_bearer": "AUTH BYPASS: 12 requests: test ALL known endpoints WITHOUT Authorization header. Test Authorization: Bearer invalid, Bearer null. Test JWT alg:none bypass. Test unsigned token with modified payload (role=admin). Test expired token.",
        "opaque_token": "AUTH BYPASS: 12 requests: test ALL known endpoints WITHOUT Authorization. Test token in URL query param (?access_token=X). Test token truncation.",
        "jwe": "AUTH BYPASS: 12 requests: test ALL known endpoints WITHOUT Authorization. Test with invalid JWE, alg:none JWE, tampered encrypted payload.",
        "cookie": "AUTH BYPASS: 12 requests: test ALL endpoints WITHOUT Cookie header. Test session=invalid, session=' OR '1'='1, session=admin. Test cookie without HttpOnly/Secure.",
        "custom": "AUTH BYPASS: 12 requests: test ALL known endpoints WITHOUT the auth header. Test empty value, invalid value, SQLi/XSS in header value.",
        "none": "AUTH BYPASS: 12 requests: test rate limiting, information disclosure, error handling on ALL known endpoints.",
    }

    return [
        f"HTTP MAP: 12-15 requests covering ALL known endpoints: {known_endpoints}. Test baseline responses with valid auth.",
        auth_templates.get(auth_type, auth_templates["jwt_bearer"]),
        "BOLA/IDOR: 15 requests: iterate user IDs 1-20 on /api/users/X, /api/orders/X, /api/wallet/X. Use GET, PUT, DELETE for each.",
        "BUSINESS LOGIC: 15 requests: POST /api/orders with quantity=-1,0,99999, price=0,-100. POST /api/wallet/transfer with amount=-1,999999. PUT /api/users/1 with role=admin, isAdmin=true.",
        "MASS ASSIGNMENT + LEAKS: 15 requests: PATCH/PUT /api/users/X with role=admin, isAdmin=true, permissions=['admin'], verified=true, balance=99999. Check every response for API keys, tokens, passwords, PII.",
        "INJECTION SWEEP: 15 requests: SQLi on all query params (' UNION SELECT, 1 OR 1=1, admin'--), XSS (<script>, <img onerror>), path traversal (../../etc/passwd), SSTI ({7*7}, ${7*7}).",
        "SSRF + RACE: 12 requests: test URL/webhook params with http://169.254.169.254, http://metadata.google.internal, file:///etc/passwd, http://127.0.0.1:8000. Then 5 concurrent requests to state-changing endpoints.",
        "EXPLOIT CHAIN + FINAL: Call bash with curl login attempts, JWT forging scripts. Then 10 requests chaining discovered exploits. Then pentest_add_findings with 5-10 confirmed findings.",
    ]


EXPLORE_ROUNDS = {
    "BASH": BASH_ROUNDS,
    "QUICK": QUICK_ROUNDS,
    "HTTP": None,  # dynamic — use build_http_rounds()
    "DISTRIBUTION": DISTRIBUTION,
}
