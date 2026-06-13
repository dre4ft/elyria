# User Guide — Elyria

**HTTP client built for API testing — from unit tests to pentesting.**

---

## 1. Overview

Elyria is a complete API client combining:

- **Structured requests** — GET, POST, PUT, PATCH, DELETE with headers, query params, and body
- **Raw HTTP requests** — forge HTTP requests from scratch (TCP socket)
- **Collections** — organize your requests in hierarchical folders, shared across teams
- **Workflow Builder** — automate multi-request scenarios with conditional logic, loops, and security tests
- **Built-in AI Assistant** — create collections, run tests, and analyze results via chat
- **Red Team / Pentest** — scan your APIs with the OWASP API Top 10 engine + AI deep scan
- **Blue Team / SSDLC** — security-by-design analysis of your specs producing security requirements reports
- **Grey Team / OSINT** — passive domain reconnaissance (DNS, WHOIS, SSL, subdomains, tech stack, emails, GitHub, Google)
- **Purple Team / IAST** — source code analysis (SAST + SCA) combined with dynamic testing (IAST), with CVE, CWE, bad practice scanning, and AI deep code review
- **OpenAPI / Arazzo import** — import your specs to auto-generate collections

---

## 2. Quick Start

### Launch

```bash
cd /path/to/elyria
uvicorn app.entrypoint:app --host 127.0.0.1 --port 8000
```

Open `https://127.0.0.1:8000` in your browser.

### First Launch

1. Click the **Sign Up** tab
2. Choose a username and password
3. Log in with those credentials

You'll land on the main interface.

---

## 3. Main Interface

The screen is divided into several areas:

| Area | Description |
|------|-------------|
| **Left sidebar** | Collections (folders + saved requests) |
| **Center area** | Request builder (structured or raw) + response panel |
| **Right panels** | History, ELY Copilot, JWT Decoder — open via header buttons |

### 3.1. The URL Bar and Sending Requests

1. Select the **HTTP method** (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
2. Enter the full **URL** (e.g. `https://api.example.com/v1/users`)
3. Click **Send** or press `Ctrl+Enter`

Query parameters are automatically extracted from the URL and displayed in the **Params** tab.

### 3.2. The Structured Builder

The **Structured** tab has 3 sub-tabs:

**Params** — Query parameters as key/value pairs.
- Enable/disable a parameter with the checkmark button
- Add with the **+ Add Parameter** button
- The **From URL** button re-parses the URL to extract parameters
- Any change is synced to the URL in real time

**Headers** — HTTP headers as key/value pairs.
- The `Content-Type` header is managed automatically based on the selected body type
- Add custom headers with the **+ Add Header** button

**Body** — Request body.
- Select the **Content-Type**: JSON, Text, XML, Form URL Encoded
- Enter content in the editor

### 3.3. The Response

After sending, the response panel displays:

- **HTTP code** with colored badge (green 2xx, blue 3xx, orange 4xx, red 5xx)
- **Response time** in milliseconds
- **Body** — auto-formatted if JSON
- **Response headers**

The panel is **resizable** — drag the handle between the builder and response.

---

## 4. Collections

Collections let you organize saved requests into folders.

### Creating a Collection

1. In the sidebar, **Collections** tab
2. Click the **+ folder** button (purple icon)
3. Give the folder a name

### Creating a Saved Request

1. Hover over a folder, click the **+** that appears on the right
2. Name the request
3. The request appears in the folder — click it to load it into the builder

### Collection Actions

| Action | How |
|--------|-----|
| **Load a request** | Single click on the request |
| **Rename a folder or request** | Double-click |
| **Delete a request** | Hover, click the trash icon |
| **Delete a folder** | Hover, click the trash icon (recursively deletes contents) |
| **Search** | Use the search bar at the top of the Collections section |

### Auto-Save

When you modify a request loaded from a collection, it is automatically saved:
- On every request send
- When switching to another request
- When leaving the page

---

## 5. History

The **History** tab (in the sidebar) keeps a list of sent requests.

- The last 50 requests are loaded automatically
- Click an entry to reload the request and its response into the builder
- The search bar filters by URL, method, or ID

---

## 7. ELY Copilot

ELY Copilot is the context-aware AI assistant integrated into every Elyria page. It knows which page you're on and tailors its actions accordingly.

### Slash Commands `/`

In the chat, type `/` to see available commands:

| Command | Description |
|---------|-------------|
| `/explain` | Analyze an HTTP response (status, headers, errors) |
| `/scan` | Launch a Red Team security scan |
| `/osint` | Launch an OSINT scan (Grey Team) |
| `/analyze` | Analyze a specification (Blue Team) |
| `/create` | Create a request, collection, or workflow |
| `/help` | Help about Elyria |

Keyboard navigation (↑↓ Enter) or mouse click in the menu. When a command is used, the AI is guided toward the corresponding action.

### Opening ELY Copilot

- **ELY Copilot** button in the top bar, or
- `Ctrl+I` shortcut

### Flash / Pro Model Toggle

The **Flash** / **Pro** toggle in the panel header lets you choose the AI model:
- **Flash**: fast responses for simple tasks
- **Pro**: deep analysis with reasoning

### Usage

1. Type your message in the field at the bottom of the panel
2. Press `Enter` to send

Example prompts:
- *"Create a collection to test the Stripe payment API"*
- *"Send a GET request to https://api.example.com/users and check that the status is 200"*
- *"Analyze the last response and tell me if the JWT token is valid"*
- *"Run a security scan on my Red Team profile"*

ELY Copilot has access to your collections, requests, workflows, scan profiles, and history. It can create, execute, and analyze based on the page you're on.

### ELY Diary

The **Diary** is a chronological event journal integrated into the ELY Copilot panel. It automatically captures snapshots of your activity and lets you browse, search, and manage them — without saving full conversations.

Key features:
- **Automatic snapshots**: Every 3 minutes and on each HTTP request sent, a contextual markdown entry is saved (method, URL, status, response preview)
- **Manual entries**: Click "Nouvelle entrée" to snapshot the current context on demand
- **Theme filtering**: Filter entries by theme — Requêtes, Scans, OSINT, Audit, Workflows, Notes
- **Full-text search**: Search across all diary entry titles and content
- **Expand/collapse**: Click an entry to view its full markdown content
- **Copy & Delete**: Copy entry content to clipboard or delete entries you no longer need
- **AI context**: ELY automatically sees your 5 most recent diary entries for contextual awareness
- **AI tools**: ELY can create, query, list, read, and delete diary entries via `ely_diary_*` actions — available on every page

**Opening the Diary**: Click the clock-icon **Diary** button next to the model toggle (Flash/Pro) in the ELY Copilot header. This replaces the chat view with the diary timeline. Click it again to return to the chat.

**Important**: The Diary saves contextual events (requests, scans, analyses) — **not** full chat conversations. Chat history remains separate in the chat panel.

---

## 8. Document Import

Import your API specifications and collections to auto-generate folders and requests.

### Supported Formats

- **OpenAPI 3.x** and **Swagger 2.x** (`.json`, `.yaml`, `.yml`)
- **Arazzo 1.0** — test workflows
- **Postman** — Postman collections (`.json`)
- **Bruno** — Bruno collections (`.json`, `.bru`)

### How to Import

1. In the import bar (at the top of the builder), click the desired format: **OpenAPI**, **cURL**, **Postman**, or **Bruno**
2. Drag and drop a file into the zone, or click to browse
3. Click **Import**

### OpenAPI Import Result

- A root folder is created with the API name
- Each operation (endpoint) becomes a saved request in a sub-folder by tag
- Parameters, headers, and example body are pre-filled

### Arazzo Import Result

- Workflows are imported as executable scenarios
- References between steps (`$steps.x.outputs.y`) are translated to `{{ctx.xxx}}` syntax

### Postman or Bruno Import Result

- Postman/Bruno folders are converted to Elyria collection folders
- Requests keep their headers, parameters, and body
- Environment variables are imported as context variables

---

## 9. Raw HTTP Requests

Raw HTTP mode lets you send hand-crafted requests to test edge cases.

### Access

Click the **Raw HTTP** tab in the builder.

### Format

```
METHOD /path HTTP/1.1
Host: example.com
Header: value

Request body
```

Example:
```
POST /api/v1/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...

{"name": "John", "email": "john@example.com"}
```

### Specifics

- The request is sent via a **raw TCP socket**, without modification
- Parsing the first line automatically extracts the method and path
- After sending, the parsed components automatically populate the Structured tab

---

## 10. Workflow Builder

The Workflow Builder lets you create automated test scenarios via drag and drop.

### Access

From the main interface, click the **Workflows** button in the top bar.

### Interface

| Area | Description |
|------|-------------|
| **Left palette** | Available blocks, grouped by category + saved collections |
| **Center canvas** | Workspace where you place and connect blocks |
| **Right panel** | Selected block configuration + execution logs |

### 10.1. Blocks

Drag and drop blocks from the palette to the canvas. Connect them by pulling from an output port (bottom circle) to an input port (top circle) of another block.

#### Flow Control

| Block | Role | Output ports |
|-------|------|--------------|
| **Start** | Required workflow entry point | `out` |
| **If / Else** | Conditional branch (JavaScript expression) | `TRUE`, `FALSE` |
| **For Loop** | Loop N iterations with an index variable | `BODY` (each iteration), `DONE` (after loop) |
| **Delay** | Pause in milliseconds | `out` |

#### Data

| Block | Role |
|-------|------|
| **Set Data** | Defines variables in the workflow context |

The **Set Data** block has two modes:
- **Without a dataset name**: variables are injected directly into `ctx` → accessible via `{{ctx.myVariable}}`
- **With a dataset name** (`Dataset name` field): variables are grouped under `ctx.datasetName` → accessible via `{{ctx.datasetName.myVariable}}`

#### Requests

| Block | Role |
|-------|------|
| **HTTP Request** | Sends a structured HTTP request (method, URL, headers, body) |
| **Raw Request** | Sends a raw HTTP request via TCP socket |

Each request block has a **Save response as** field that determines under which name the response is stored in the context (default: `response`).

#### Assertions

| Block | Role |
|-------|------|
| **Assert** | Checks a condition — the workflow fails if the condition is false |

The Assert block's config panel offers ready-to-use example snippets.

#### Red Team / Security

| Block | Role | Output ports |
|-------|------|--------------|
| **Fuzz Request** | Fuzzing loop over a wordlist | `BODY` (each iteration), `DONE` (after loop) |
| **BOLA Test** | IDOR test — substitutes IDs into the URL | `VULN` (if 200), `SAFE` (otherwise) |
| **JWT Analyze** | Decodes a JWT token: header/payload, expiration check | `out` |
| **Response Diff** | Compares two HTTP responses (status, headers, body) | `out_diff` (different), `out_same` (identical) |
| **Extract & Replay** | Extracts a value from a response and replays it in a new request | `out` |

**Fuzz Request** — Fuzzing loop
- **Wordlist** field: one value per line. At each iteration, `ctx.fuzz` contains the current value.
- `BODY` output: connect to an HTTP request. In the request, use `{{ctx.fuzz}}` in the URL, headers, or body.
- The request output MUST loop back to the `in` input of the Fuzz block.
- `DONE` output: once the wordlist is exhausted. `ctx[saveTo]` contains `{ iterations: N, results: [...] }`.

**BOLA Test** — IDOR (Insecure Direct Object Reference) test
- **ID List (JSON)** field: mapping of IDs to substitute.
- Place `{{id}}` in the upstream request URL. The block substitutes each ID and checks if the resource is accessible (HTTP 200).
- `VULN` output if another user's resource is accessible.
- `SAFE` output if all requests return 403/404.

**JWT Analyze** — JWT decoder
- Decodes the header and payload of a JWT token in `ctx.jwt` or `ctx.response.body`.
- Checks expiration (`exp`) and issued-at (`iat`).
- Stores results in `ctx.jwt_analysis`: `{ header, payload, expired, issued_at, expires_at }`.

**Response Diff** — Response comparison
- Compares the last two responses stored in `ctx`. Detects differences in status, headers, and body.
- Useful for comparing before/after a change (e.g., admin vs normal user request).
- `out_diff` if responses differ, `out_same` if identical.

**Extract & Replay** — Extract and re-execute
- Extracts a value from a response using a regular expression and reinjects it into a new request.
- Useful for extracting a CSRF token, resource ID, or JWT token and reusing it.
- Stores the extracted value in `ctx.extracted_value`.

### 10.2. Context (ctx)

All blocks share a `ctx` object that flows through the workflow.

**Template syntax**: `{{ctx.path.to.value}}`

| Expression | Description |
|------------|-------------|
| `{{ctx.response.status_code}}` | HTTP code of the last response |
| `{{ctx.response.body}}` | Body of the last response |
| `{{ctx.response.headers["Content-Type"]}}` | Specific response header |
| `{{ctx.response.url}}` | Response URL |
| `{{ctx.datasetName.field}}` | Field of a named dataset (Set Data with name) |
| `{{ctx.myVariable}}` | Root variable defined by Set Data |

**Variables injected by Red Team blocks:**

| Variable | Injected by | Description |
|----------|-------------|-------------|
| `{{ctx.fuzz}}` | Fuzz Request | Current wordlist value (one per iteration) |
| `{{ctx.fuzzResults}}` | Fuzz Request | Full results after loop: `{ iterations, results }` |
| `{{ctx.id_list}}` | BOLA Test | One ID from the list per iteration |
| `{{ctx.jwt_analysis}}` | JWT Analyze | Decode result: `{ header, payload, expired }` |
| `{{ctx.extracted_value}}` | Extract & Replay | Value extracted by the regex |

**Ctx snippets**: in the config panel of HTTP Request, Raw Request, Set Data, and If/Else blocks, a *ctx — Workflow context* section shows clickable snippets that insert at the cursor position in the active field.

### 10.3. Execution

1. Place a **Start** block on the canvas
2. Add your blocks and connect them in the desired order
3. Click **Run** (green button at the top)
4. Execution logs appear in the **Logs** tab of the right panel

During execution, blocks change color:
- **Yellow** = running
- **Green** = success
- **Red** = error

You can **stop** execution at any time with the Stop button.

### Canvas Actions

| Action | How |
|--------|-----|
| **Select a block** | Click the block |
| **Move a block** | Drag and drop |
| **Delete a block** | Click the × (appears on hover) or press `Delete` |
| **Create a connection** | Drag from an output port to an input port |
| **Select a connection** | Click the link |
| **Delete a connection** | Select it then press `Delete` |
| **Zoom** | +/− buttons or scroll wheel |
| **Clear all** | Clear button |

---

## 11. The Hub

The Hub (accessible via the user icon in the header) centralizes your account and resource management.

### 11.1. Teams

- **Create a team**: click "Creer", give it a name. You're automatically a member.
- **Join a team**: enter a Team ID and click "Rejoindre". A request is sent to members.
- **Validate a request**: expand the team to see pending requests. Validation requires 80% member approval.
- **Follow/Unfollow**: followed teams appear in your collection, workflow and pentest filters.
- **Copy ID**: click the copy icon next to the Team ID.

### 11.2. Server Configuration (`elyria.cfg`)

Elyria is configured via the **`elyria.cfg`** file at the project root. It's a standard INI file with no `.env` dependency.

**Available sections:**

```ini
[server]
host = 127.0.0.1     # Listen address
port = 8000          # Port
reload = 1           # Hot reload (0 in production)

[ssl]
cert_path = cert.pem # TLS certificate path
key_path = key.pem   # Private key path
verify = 0           # Outbound SSL verification (1 in production)

[database]
backend = sqlite     # sqlite or postgres
sqlite_path = database.db
pg_host = localhost  # PostgreSQL (if backend=postgres)
pg_port = 5432
pg_database = elyria
pg_user = elyria
pg_password = elyria

[logging]
level = INFO         # DEBUG, INFO, WARNING, ERROR
dir = logs

[oidc]
enabled = 0          # 1 to enable SSO
provider_name =      # Provider name
issuer =             # OIDC discovery URL
client_id =          # Client ID
client_secret =      # Client Secret

[security]
server_wrap_key =    # Encryption key (64 hex chars). Generated if absent.
blocked_hosts = metadata.google.internal,169.254.169.254,host.docker.internal
```

**Priority order:**
1. Environment variables `ELYRIA_*` (e.g., `ELYRIA_SERVER_PORT=9000`)
2. Database `app_config` (modifiable via admin API)
3. `elyria.cfg` file
4. Hard-coded defaults

**Env var override** format: `ELYRIA_SECTION_KEY`. Examples:
- `ELYRIA_SERVER_PORT=9000` → `[server].port`
- `ELYRIA_DATABASE_PG_PASSWORD=secret` → `[database].pg_password`

### 11.3. Proxy

Configure HTTP proxies for request forwarding.

- **Add**: name + URL (e.g., `http://proxy:8080`).
- **Set as favorite**: the favorite proxy is injected into your requests when active.
- **Delete**: X icon on each proxy.

### 11.4. AI Agent

Manage your LLM providers for AI chat and pentest AI scanning.

- **Two independent slots**:
  - **Flash Model**: used for fast exploration (parallel request batches)
  - **Pro Model**: used for deep analysis and the main AI chat
- **Each slot can use a different provider** (e.g., Flash on local Ollama, Pro on OpenAI API cloud)
- **Supported providers**: OpenAI/DeepSeek, LM Studio (local), Ollama (local)
- **List models**: after configuring the URL, click "Lister" to see available models
- **Set as default**: only one provider per slot can be the default
- **Security**: API keys are never returned to the frontend (masked `****`). You can replace them but not read them.

## 12. Red Team / Pentest

The Red Team module (accessible via header or `/pentest`) scans your APIs with the OWASP API Top 10 engine.

### 12.1. Scan Profiles

- **Create a profile**: "+" button in the "Scan Profiles" sidebar
- **Configure**: target URL, authentication (Bearer, headers), OpenAPI spec, ID list (for BOLA), existing collection, team
- **AI tab**: set the number of exploration rounds (1-50, default 15) and analysis rounds (1-25, default 5)
    - **Expert Mode**: enable the Expert option for an in-depth scan (30 exploration rounds, 15 analysis rounds, detailed documentation-driven report)
- **Edit**: pencil icon on the profile
- **Delete**: X icon on the profile

### 12.2. Campaigns

- **Launch a scan**: select a profile, click "Lancer le scan". A campaign is created.
- **Progress**: progress bar with color gradient (red → orange → purple)
- **Stop**: Stop button during the scan
- **Delete**: X icon on each campaign (full purge: findings, logs, campaign)
- **Refresh**: Refresh button in the header or automatic every 60s

### 12.3. Sandbox (Bash Tool)

During **Phase 2** (AI Deep Scan), Elyria automatically spawns a **disposable Docker container** (`strike-sandbox`) — an isolated Linux environment with real pentest tools that the AI can invoke.

#### Tools available in the container

| Tool | Usage |
|------|-------|
| **nmap** | Port scanning, service and OS detection |
| **sqlmap** | SQL injection detection and exploitation |
| **nuclei** | 5000+ vulnerability templates (CVEs, misconfigs, exposures) |
| **ffuf** | Web fuzzer (path, parameter, subdomain brute force) |
| **subfinder** | Subdomain enumeration via passive sources |
| **curl, jq, python3** | HTTP scripting, JSON parsing, Python scripting (requests, httpx, pyjwt) |

#### How the AI interacts with the sandbox

The AI agent uses a single **`bash` tool** exposed via the OpenAI function calling protocol. The AI autonomously decides which commands to execute based on what it discovers. The tool accepts:

- **Single mode**: one command (`"command": "nmap -sV TARGET"`)
- **Batch mode**: up to 10 commands executed sequentially (`"commands": ["cmd1", "cmd2"]`)
- **Timeout**: configurable per command (default 30s, max 60s)

The `TARGET` keyword in commands is automatically replaced with the actual scan target.

#### Container lifecycle

1. **Spawn** — `SandboxManager.spawn()` creates a Docker container named `strike-{unique_id}` with `--rm`, limited to 1 CPU and 512 MB RAM
2. **Idle** — The entrypoint waits for commands (`tail -f /dev/null`) while monitoring a **30-minute TTL** (configurable)
3. **Execution** — Each command is injected via `docker exec`: base64-encoded to avoid shell escaping issues, decoded inside the container, then executed in bash. Stdout (50k chars max) and stderr (10k max) are captured
4. **Destroy** — At scan end (or if stopped), `docker rm -f --volumes` destroys the container and its volumes

#### Localhost resolution

`127.0.0.1` and `localhost` in commands or targets are automatically converted to **`host.docker.internal`** so the container can reach the host.

#### Sanitization

- **Target**: only `[a-zA-Z0-9.\-:/_@?=&%#]` characters kept, limited to 2000 characters
- **Commands**: destructive patterns explicitly blocked (`rm -rf /`, fork bombs, `/etc/shadow`, etc.)
- **Isolation**: Alpine `--rm` container, resource-limited, no disk persistence

#### Passive mode (Grey Team)

For Grey Team (OSINT) scans, the sandbox is **optional** and restricted to **passive-only** tools: `nmap`, `sqlmap`, `ffuf`, `nuclei` and other active tools are blocked. Only `dig`, `whois`, `curl` to public APIs (crt.sh, archive.org), `python3`, and `jq` are allowed.

#### Logging

Every bash command executed by the AI is logged in the database (`pentest_scan_logs`, `log_type='bash'`) with stdout, stderr, exit code, and execution time — visible in the **Logs** tab of the campaign.

### 12.4. Findings and Logs

- **Dashboard**: severity counters (Critical, High, Medium, Low, Info)
- **Findings**: each vulnerability shows title, severity, description, remediation, CWE/CVSS
- **Request/Response details**: click a finding to see Request/Response tabs (URL, headers, body)
- **AI Analysis**: AI agent findings include a short 3-sentence analysis
- **Logs**: history of all requests sent during the scan, with request/response details on click
- **Severity filter**: dropdown in the Findings tab
- **Refresh**: Refresh buttons in each tab

### 12.5. Report

- **Markdown Report**: available in the Report tab
- **Quick navigation**: sticky table of contents with main sections
- **Download**: Report button in the header to export as .md
- **Appendices**: request/response details for each finding

## 13. Blue Team / SSDLC

The Blue Team module (accessible via the header or `/blueteam`) analyzes your API specifications with an expert security-by-design AI agent to produce a comprehensive security requirements report.

### 13.1. SSDLC Profiles

- **Create a profile**: "+" button in the "SSDLC Profiles" sidebar
- **Configure**: target URL, Master Prompt (agent instructions), Documentation (business context), OpenAPI spec, collection
- **Team filter**: dropdown in the sidebar to filter profiles by team
- **Edit**: pencil button in the profile header
- **Delete**: trash button in the profile header

### 13.2. Analysis

- **Start analysis**: select a profile, click "Start Analysis"
- **Progress**: progress bar + real-time status messages (adaptive polling)
- **Stop**: Stop button during analysis
- **Pro Model**: badge showing the AI model in use

### 13.3. Report

The AI agent analyzes your spec across 8 security domains:
1. Authentication & Authorization
2. Data Protection (transit, storage, processing)
3. Input Validation & Injection
4. API Architecture (rate limiting, versioning, CORS)
5. Error Handling & Logging
6. Business Logic & Workflows
7. Supply Chain & Dependencies
8. Compliance & Governance (GDPR, PCI-DSS, SOC2)

The report includes:
- Executive summary with security maturity score
- Domain-by-domain analysis (strengths, weaknesses, risks)
- Security requirements table with priorities and OWASP/NIST references
- Prioritized action plan (immediate, short-term, medium-term)
- Mermaid diagrams illustrating attack flows and target architecture

### 13.4. Import from Red Team

You can import a Red Team campaign to generate a remediation plan:
- From Red Team, "Send to Blue Team" button on a completed campaign
- Or from Blue Team, use the `POST /api/blueteam/import-from-pentest` API

---

## 14. Grey Team / OSINT

The Grey Team module (accessible via the header or `/greyteam`) performs **passive reconnaissance** (OSINT) on a target domain. Unlike Red Team which actively attacks, Grey Team collects public information without directly interacting with target servers.

### 14.1. OSINT Profiles

- **Create a profile**: "+" button in the "Domains" sidebar
- **Configure**: name, target domain, description, OSINT modules, AI analysis rounds
- **Team filter**: dropdown in the sidebar
- **Edit**: Edit button in the dashboard header
- **Delete**: Delete button in the dashboard header

### 14.2. Dashboard

- **Risk Score**: 0-100 gauge based on finding count and severity
- **Counters**: Critical, High, Total Findings
- **6 indicator cards**: DNS Health, SSL/TLS, HTTP Security, Subdomains, Email Exposure, Tech Stack
- **Scan progress**: progress bar with adaptive polling

### 14.3. OSINT Modules (Phase 1)

13 passive collection modules running in parallel: DNS Records, WHOIS, SSL/TLS, Cert Transparency (crt.sh + Cert Spotter + AlienVault OTX), HTTP Headers, Web Paths, Tech Fingerprint (30+ patterns: CMS, frameworks, CDN/WAF), Email Enumeration, Trivial Pages (190+ paths: .env, .git, wp-admin, backups, configs), Wayback Machine, GitHub Dorks, Google Dorks, Frontend Code (secrets, API endpoints, CVEs, AI deobfuscation).

### 14.4. Phase 2 — AI Refinement

The AI agent (Flash + Pro models) enriches findings:

- **osint_refine_finding**: exploitability score (1-10), MITRE ATT&CK vector, remediation priority
- **osint_create_finding**: creates new findings discovered during analysis
- **osint_correlate_findings**: chains findings into attack scenarios
- **bash**: passive OSINT commands in sandbox (dig, whois, curl crt.sh/archive.org/GitHub API)

### 14.5. Findings and Filters

- Table sorted by severity with title, category, description
- **Filters**: severity, module type, source (Deterministic / AI Refined)
- **Detail panel**: description, evidence, remediation, AI analysis
- **Automatic refresh** during the scan

---

## 15. Purple Team / IAST

The Purple Team module (accessible via the header or `/purpleteam`) combines **SAST** (Static Application Security Testing), **SCA** (Software Composition Analysis), and **IAST** (Interactive Application Security Testing) to analyze your source code.

### 15.1. Scan Profiles

- **Create a profile**: "+" button in the "Repositories" sidebar
- **Configure**:
  - **Repo Source**: GitHub, GitLab, Bitbucket, or local (zip upload)
  - **Repository URL**: Git repository URL (e.g. `https://github.com/user/repo.git`)
  - **Auth**: Bearer Token or API Key (optional, for private repos)
  - **Target Endpoint**: Live API URL for dynamic IAST testing (optional)
  - **OpenAPI Spec URL**: OpenAPI specification to guide testing
  - **Scan Depth**: Quick (static only), Full (static + AI), IAST (static + dynamic)
- **Edit**: Edit button in the header
- **Delete**: Delete button in the header

### 15.2. Scan Phases

The Purple Team scan runs in three phases:

| Phase | Description |
|-------|-------------|
| **Phase 1 — Static Analysis** | Language/framework detection, dependency parsing, CVE scanning (NIST NVD), CWE pattern matching (25+ patterns), bad practice detection (30+ patterns) |
| **Phase 2 — Dynamic IAST** | If a target endpoint is provided: validation of static findings against the live API, configuration tests (headers, CORS, HTTP methods, error disclosure, auth bypass) |
| **Phase 3 — AI Deep Code Review** | The AI agent reads source code, greps for patterns, makes HTTP requests to the target API, and reports confirmed vulnerabilities (business logic, auth flaws, crypto weaknesses, race conditions) |

### 15.3. Three-Part Report

The Purple Team report is structured in three sections:

1. **Known CVEs** — CVE vulnerabilities found in dependencies (via NIST NVD), with CVSS scores
2. **CWE (Common Weakness Enumeration)** — Code weaknesses classified by CWE ID (CWE-79 XSS, CWE-89 SQLi, CWE-78 CMDi, CWE-798 Hardcoded Credentials, etc.)
3. **Bad Practices & Exploitations** — Debug mode, hardcoded secrets, permissive CORS, disabled auth, weak crypto, + AI-discovered findings (business logic, IDOR, race conditions)

### 15.4. Findings and Filters

- **Dashboard**: CVE, CWE, Practices, Critical, High counters
- **Filters**: by part (CVE, CWE, Practices, AI Discovered) and by severity
- **AI Badge**: AI-discovered findings are marked with a purple `AI` badge
- **Detail panel**: severity, title, category, CVE/CWE, location (file:line), CVSS, description, remediation, AI analysis
- **Report**: full markdown view in the interface, .md download

### 15.5. Send to Blue Team

Like Red Team, you can send a Purple Team report to Blue Team for remediation:
- **Send to Blue Team** button after a completed scan
- Automatically creates a Blue Team profile with a Purple Team-specific prompt
- Blue Team analysis starts automatically

### 15.6. Clone Security

- **Docker Sandbox**: if Docker is available, repo cloning happens inside an isolated container — auth tokens never touch the host filesystem
- **Direct fallback**: if Docker is unavailable, direct clone with `--depth 1` and immediate `.git` removal
- **Auto-purge**: cloned files are automatically deleted after the scan

---

## 16. Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Enter` | Send current request |
| `Ctrl+I` | Open/close AI assistant |
| `Delete` | Delete selected block (workflow) |
| `Delete` | Delete selected connection (workflow) |
| `Escape` | Close modals |
| `Enter` | Confirm in modals |
