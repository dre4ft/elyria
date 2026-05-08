# User Guide — Elyria

**HTTP client built for API testing — from unit tests to pentesting.**

---

## Table of Contents

1. [Overview](#1--overview)
2. [Quick Start](#2--quick-start)
3. [Main Interface](#3--main-interface)
   - [The URL Bar and Sending Requests](#31--the-url-bar-and-sending-requests)
   - [The Structured Builder](#32--the-structured-builder)
   - [The Response](#33--the-response)
4. [Collections](#4--collections)
5. [History](#5--history)
6. [AI Assistant](#6--ai-assistant)
7. [Document Import (OpenAPI / Arazzo)](#7--document-import-openapi--arazzo)
8. [Raw HTTP Requests](#8--raw-http-requests)
9. [Workflow Builder](#9--workflow-builder)
   - [Blocks](#91--blocks)
   - [Context (ctx)](#92--context-ctx)
   - [Execution](#93--execution)
10. [Keyboard Shortcuts](#10--keyboard-shortcuts)

---

## 1. Overview

Elyria is a complete API client combining:

- **Structured requests** — GET, POST, PUT, PATCH, DELETE with headers, query params, and body
- **Raw HTTP requests** — forge HTTP requests from scratch (TCP socket)
- **Collections** — organize your requests in hierarchical folders
- **Workflow Builder** — automate multi-request scenarios with conditional logic and loops
- **Built-in AI Assistant** — create collections, run tests, and analyze results via chat
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

The screen is divided into 3 areas:

| Area | Description |
|------|-------------|
| **Left sidebar** | Collections (folders + saved requests) and History |
| **Center area** | Request builder (structured or raw) + response panel |
| **Chat panel (right)** | AI Assistant, hidden by default, opens with the **AI Assistant** button or `Ctrl+I` |

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

## 6. AI Assistant

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

## 7. Document Import (OpenAPI / Arazzo)

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

## 8. Raw HTTP Requests

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

## 9. Workflow Builder

The Workflow Builder lets you create automated test scenarios via drag and drop.

### Access

From the main interface, click the **Workflows** button in the top bar.

### Interface

| Area | Description |
|------|-------------|
| **Left palette** | Available blocks, grouped by category + saved collections |
| **Center canvas** | Workspace where you place and connect blocks |
| **Right panel** | Selected block configuration + execution logs |

### 9.1. Blocks

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

### 9.2. Context (ctx)

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

### 9.3. Execution

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

## 10. Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Enter` | Send current request |
| `Ctrl+I` | Open/close AI assistant |
| `Delete` | Delete selected block (workflow) |
| `Delete` | Delete selected connection (workflow) |
| `Escape` | Close modals |
| `Enter` | Confirm in modals |
