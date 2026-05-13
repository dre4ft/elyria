# User Guide — Elyria

**HTTP client built for API testing — from unit tests to pentesting.**

---

## Table of Contents

1. [Overview](#1--overview)
2. [Quick Start](#2--quick-start)
3. [Main Interface](#3--main-interface)
4. [Collections](#4--collections)
5. [History](#5--history)
6. [Catcher (Proxy Interceptor)](#6--catcher-proxy-interceptor)
7. [AI Assistant](#7--ai-assistant)
8. [Document Import (OpenAPI / Arazzo)](#8--document-import-openapi--arazzo)
9. [Raw HTTP Requests](#9--raw-http-requests)
10. [Workflow Builder](#10--workflow-builder)
11. [The Hub](#11--the-hub)
12. [Red Team / Pentest](#12--red-team--pentest)
13. [Blue Team / SSDLC](#13--blue-team--ssdlc)
14. [Keyboard Shortcuts](#14--keyboard-shortcuts)

---

## 1. Overview

Elyria is a complete API client combining:

- **Structured requests** — GET, POST, PUT, PATCH, DELETE with headers, query params, and body
- **Raw HTTP requests** — forge HTTP requests from scratch (TCP socket)
- **Collections** — organize your requests in hierarchical folders, shared across teams
- **Workflow Builder** — automate multi-request scenarios with conditional logic, loops, and security tests
- **Catcher** — Burp Suite-style proxy interceptor to inspect browser or Postman requests
- **Built-in AI Assistant** — create collections, run tests, and analyze results via chat
- **Red Team / Pentest** — scan your APIs with the OWASP API Top 10 engine + AI deep scan
- **Blue Team / SSDLC** — security-by-design analysis of your specs producing security requirements reports
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
| **Right panels** | History, Catcher, AI Assistant, JWT Decoder — open via header buttons |

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

## 6. Catcher (Proxy Interceptor)

The Catcher is a Burp Suite-style HTTP forward proxy that intercepts requests from your browser or Postman for inspection.

### Activation

1. Click the **Catcher** button (pink) in the top bar
2. In the panel, click **Intercept OFF** to enable interception → the button becomes **Intercept ON**
3. A `Proxy: localhost:8080` badge appears — this is the proxy address

### Browser / Postman Configuration

- **Browser**: network settings → HTTP proxy → `localhost:8080`
- **Postman**: Settings → Proxy → `localhost:8080`
- **Command line**: `curl -x http://localhost:8080 https://api.example.com`

### Pending Queue

When **Intercept ON** is active, requests are queued instead of being sent directly. The first request appears in expanded mode:

- **Method**: editable dropdown
- **URL**: editable field
- **Headers**: editable textarea
- **Body**: editable textarea

Fields are live-editable — changes are saved automatically.

### Actions

| Action | Description |
|--------|-------------|
| **Forward** | Executes the request to the target and returns the response to the client |
| **Drop** | Dismisses the request, client receives 410 Gone |
| **Load** | Loads the request into the Elyria API builder |

### History

All forwarded and dropped requests are persisted in the history. Each entry shows:
- Method, HTTP status code, URL
- **Load** button to load into the API builder
- Click a row to expand the response body detail

History is scoped per user.

### Proxy Port

Configurable via the `CATCHER_PORT` environment variable (default: 8080).

---

## 7. AI Assistant

The AI assistant can create collections, send requests, and analyze results.

### Opening the Assistant

- **AI Assistant** button in the top bar, or
- `Ctrl+I` shortcut

### Usage

1. Type your message in the field at the bottom of the panel
2. Press `Enter` to send

Example prompts:
- *"Create a collection to test the Stripe payment API"*
- *"Send a GET request to https://api.example.com/users and check that the status is 200"*
- *"Analyze the last response and tell me if the JWT token is valid"*

The assistant has access to your collections, can create folders, requests, execute them, and read history.

---

## 8. Document Import (OpenAPI / Arazzo)

Import your API specifications to auto-generate collections.

### Supported Formats

- **OpenAPI 3.x** and **Swagger 2.x** (`.json`, `.yaml`, `.yml`)
- **Arazzo 1.0** — test workflows

### How to Import

1. Click the **Documents** button in the top bar
2. Drag and drop a file into the zone, or click to browse
3. Click **Import**

### OpenAPI Import Result

- A root folder is created with the API name
- Each operation (endpoint) becomes a saved request in a sub-folder by tag
- Parameters, headers, and example body are pre-filled

### Arazzo Import Result

- Workflows are imported as executable scenarios
- References between steps (`$steps.x.outputs.y`) are translated to `{{ctx.xxx}}` syntax

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

### 11.2. Proxy

Configure HTTP proxies for request forwarding.

- **Add**: name + URL (e.g., `http://proxy:8080`).
- **Set as favorite**: the favorite proxy is injected into your requests when active.
- **Delete**: X icon on each proxy.

### 11.3. AI Agent

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
- **Edit**: pencil icon on the profile
- **Delete**: X icon on the profile

### 12.2. Campaigns

- **Launch a scan**: select a profile, click "Lancer le scan". A campaign is created.
- **Progress**: progress bar with color gradient (red → orange → purple)
- **Stop**: Stop button during the scan
- **Delete**: X icon on each campaign (full purge: findings, logs, campaign)
- **Refresh**: Refresh button in the header or automatic every 60s

### 12.3. Findings and Logs

- **Dashboard**: severity counters (Critical, High, Medium, Low, Info)
- **Findings**: each vulnerability shows title, severity, description, remediation, CWE/CVSS
- **Request/Response details**: click a finding to see Request/Response tabs (URL, headers, body)
- **AI Analysis**: AI agent findings include a short 3-sentence analysis
- **Logs**: history of all requests sent during the scan, with request/response details on click
- **Severity filter**: dropdown in the Findings tab
- **Refresh**: Refresh buttons in each tab

### 12.4. Report

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

## 14. Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Enter` | Send current request |
| `Ctrl+I` | Open/close AI assistant |
| `Delete` | Delete selected block (workflow) |
| `Delete` | Delete selected connection (workflow) |
| `Escape` | Close modals |
| `Enter` | Confirm in modals |
