# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Call graph builder — traces method/function calls from REST controllers
through the codebase to build a deep understanding of application logic.

Produces:
  1. Call graph: controller → handler → service → repository → DB
  2. Data flow: user input → transformations → sensitive sinks
  3. Auth gate map: which endpoints are protected, which are not
  4. Sink detection: SQL queries, command execution, file ops, deserialization
"""

import os
import re
import json


def build_call_graph(repo_path: str, language: str, framework: str,
                     controllers: list[dict]) -> dict:
    """Build a directed call graph from controllers through the codebase."""
    builder = _BUILDERS.get(language, _build_generic)
    return builder(repo_path, framework, controllers)


# ═══════════════════════════════════════════════════════════════════
# Call graph data structure
# ═══════════════════════════════════════════════════════════════════
# {
#   "controllers": [...],
#   "functions": {name: {file, line, calls: [...], called_by: [...], sinks: [...]}},
#   "auth_gates": [{controller, type: "middleware|decorator|guard|none"}],
#   "sinks": [{file, line, type: "sql|command|file|deserialize|eval", code: "..."}],
# }


# ═══════════════════════════════════════════════════════════════════
# Python call graph
# ═══════════════════════════════════════════════════════════════════

def _build_python(repo_path: str, framework: str, controllers: list[dict]) -> dict:
    graph = {
        'controllers': controllers,
        'functions': {},
        'auth_gates': [],
        'sinks': [],
    }

    func_def_re = re.compile(
        r'(?:async\s+)?def\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)(?:\s*->\s*\S+)?\s*:',
        re.MULTILINE,
    )
    call_re = re.compile(
        r'(?:self\.)?(?P<func>\w+)\s*\([^)]*\)',
    )
    # Sensitive sinks
    sql_re = re.compile(r'(?:execute|executemany|cursor\.execute|raw|extra)\s*\(', re.IGNORECASE)
    cmd_re = re.compile(r'(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|exec|eval)\s*\(', re.IGNORECASE)
    file_re = re.compile(r'(?:open|read|write|readlines|writelines)\([^)]*(?:request\.|\.get\(|\.post\(|\.body|\.data)', re.IGNORECASE)
    deser_re = re.compile(r'(?:pickle\.(?:loads|load)|yaml\.load\s*\(|json\.loads\([^)]*request|marshal\.loads)\s*\(', re.IGNORECASE)
    redirect_re = re.compile(r'(?:redirect|url_for|HttpResponseRedirect)\s*\(', re.IGNORECASE)

    sink_patterns = [
        ('sql_injection', sql_re),
        ('command_injection', cmd_re),
        ('path_traversal', file_re),
        ('deserialization', deser_re),
        ('open_redirect', redirect_re),
    ]

    # Walk all Python files
    from .controller_scanner import _walk_sources
    for fpath in _walk_sources(repo_path, ('.py',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        relpath = os.path.relpath(fpath, repo_path)

        # Find all function definitions
        for m in func_def_re.finditer(content):
            func_name = m.group('name')
            args = m.group('args')
            start = m.start()
            end = m.end()
            line = content[:start].count('\n') + 1

            # Find calls within this function body
            body = _extract_function_body(content, end)
            calls = []
            for cm in call_re.finditer(body):
                called = cm.group('func')
                if called != func_name and not called.startswith('_'):
                    calls.append(called)

            # Detect sinks
            sinks = []
            for sink_type, pattern in sink_patterns:
                for sm in pattern.finditer(body):
                    sinks.append({
                        'type': sink_type,
                        'code': body[max(0, sm.start()-20):sm.end()+40].strip()[:120],
                        'line': line + body[:sm.start()].count('\n'),
                    })

            graph['functions'][f'{relpath}:{func_name}'] = {
                'name': func_name,
                'file': relpath,
                'line': line,
                'args': [a.strip().split(':')[0].strip() for a in args.split(',') if a.strip() and a.strip() != 'self'],
                'calls': calls,
                'sinks': sinks,
            }

        # Find all sinks (even outside functions)
        for sink_type, pattern in sink_patterns:
            for sm in pattern.finditer(content):
                sink_line = content[:sm.start()].count('\n') + 1
                graph['sinks'].append({
                    'type': sink_type,
                    'file': relpath,
                    'line': sink_line,
                    'code': content[max(0, sm.start()-20):sm.end()+60].strip()[:150],
                })

    # Build called_by links
    for key, func in graph['functions'].items():
        for called in func['calls']:
            for other_key, other_func in graph['functions'].items():
                if other_func['name'] == called:
                    other_func.setdefault('called_by', []).append(key)

    # Auth gates — detect auth decorators
    auth_decorator_re = re.compile(
        r'@(?:(?:jwt|token|login|auth|permission|role)_required|require_(?:auth|login|role|permission)|'
        r'login_required|verify_(?:auth|token|jwt)|authenticated|has_permission|requires_auth)',
        re.IGNORECASE,
    )

    for ctrl in controllers:
        fpath = os.path.join(repo_path, ctrl.get('file', ''))
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        # Look for auth decorators near the handler
        handler = ctrl.get('handler', '')
        if handler:
            handler_re = re.compile(
                rf'(?:@\w+\([^)]*\)\s*)*\s*(?:async\s+)?def\s+{handler}\s*\(',
            )
            hm = handler_re.search(content)
            if hm:
                ctx = content[max(0, hm.start()-500):hm.start()]
                auth_m = auth_decorator_re.search(ctx)
                graph['auth_gates'].append({
                    'controller': ctrl,
                    'type': 'decorator' if auth_m else 'none',
                    'decorator': auth_m.group(0) if auth_m else None,
                })

    return graph


def _extract_function_body(content: str, start_pos: int) -> str:
    """Extract function body by tracking indentation."""
    lines = content[start_pos:].split('\n')
    body_lines = []
    for line in lines[1:]:
        if line.strip() == '':
            body_lines.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0 and line.strip() and not line.strip().startswith('#'):
            break
        if indent <= 2 and line.strip() and not line.strip().startswith('#'):
            break
        body_lines.append(line)
    return '\n'.join(body_lines)


# ═══════════════════════════════════════════════════════════════════
# Java/Spring call graph
# ═══════════════════════════════════════════════════════════════════

def _build_java(repo_path: str, framework: str, controllers: list[dict]) -> dict:
    graph = {
        'controllers': controllers,
        'functions': {},
        'auth_gates': [],
        'sinks': [],
    }

    method_re = re.compile(
        r'(?:public|private|protected)\s+(?:static\s+)?(?:\w+(?:<[^>]+>)?\s+)?'
        r'(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:\{|throws)',
    )
    call_re = re.compile(r'(?:\w+\.)?(?P<func>\w+)\s*\([^)]*\)')
    sql_re = re.compile(r'(?:executeQuery|executeUpdate|createQuery|createNativeQuery|\.query\(|jdbcTemplate\.)\s*\(', re.IGNORECASE)
    cmd_re = re.compile(r'(?:Runtime\.exec|ProcessBuilder|ScriptEngine\.eval)\s*\(', re.IGNORECASE)
    file_re = re.compile(r'(?:FileInputStream|FileReader|Files\.read|Files\.write|\.getResourceAsStream)\s*\(', re.IGNORECASE)
    deser_re = re.compile(r'(?:ObjectMapper\.readValue|SerializationUtils\.deserialize|readObject)\s*\(', re.IGNORECASE)

    sink_patterns = [
        ('sql_injection', sql_re),
        ('command_injection', cmd_re),
        ('path_traversal', file_re),
        ('deserialization', deser_re),
    ]

    from .controller_scanner import _walk_sources
    for fpath in _walk_sources(repo_path, ('.java',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        relpath = os.path.relpath(fpath, repo_path)

        for m in method_re.finditer(content):
            func_name = m.group('name')
            args = m.group('args')
            start = m.start()
            line = content[:start].count('\n') + 1
            body = _extract_java_body(content, m.end())
            calls = list(set(call_re.findall(body)))

            sinks = []
            for sink_type, pattern in sink_patterns:
                for sm in pattern.finditer(body):
                    sinks.append({
                        'type': sink_type,
                        'code': body[max(0, sm.start()-20):sm.end()+40].strip()[:120],
                        'line': line + body[:sm.start()].count('\n'),
                    })

            graph['functions'][f'{relpath}:{func_name}'] = {
                'name': func_name,
                'file': relpath,
                'line': line,
                'args': [a.strip().split()[-1] for a in args.split(',') if a.strip()],
                'calls': calls,
                'sinks': sinks,
            }

        for sink_type, pattern in sink_patterns:
            for sm in pattern.finditer(content):
                graph['sinks'].append({
                    'type': sink_type,
                    'file': relpath,
                    'line': content[:sm.start()].count('\n') + 1,
                    'code': content[max(0, sm.start()-20):sm.end()+60].strip()[:150],
                })

    # Auth gates for Spring
    for ctrl in controllers:
        fpath = os.path.join(repo_path, ctrl.get('file', ''))
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        auth_re = re.compile(r'@(?:PreAuthorize|Secured|RolesAllowed|Authenticated)\s*\(?[^)]*\)?', re.IGNORECASE)
        handler = ctrl.get('handler', '')
        if handler:
            handler_re = re.compile(rf'{handler}\s*\([^)]*\)\s*\{{0,2}}')
            hm = handler_re.search(content)
            if hm:
                ctx = content[max(0, hm.start()-800):hm.start()]
                auth_m = auth_re.search(ctx)
                graph['auth_gates'].append({
                    'controller': ctrl,
                    'type': 'annotation' if auth_m else 'none',
                    'gate': auth_m.group(0) if auth_m else None,
                })

    return graph


def _extract_java_body(content: str, start_pos: int) -> str:
    """Extract Java method body by tracking brace depth."""
    depth = 0
    started = False
    body_chars = []
    for ch in content[start_pos:]:
        if ch == '{':
            depth += 1
            started = True
        elif ch == '}':
            depth -= 1
            if started and depth == 0:
                break
        if started:
            body_chars.append(ch)
    return ''.join(body_chars)


# ═══════════════════════════════════════════════════════════════════
# JavaScript/TypeScript call graph
# ═══════════════════════════════════════════════════════════════════

def _build_javascript(repo_path: str, framework: str, controllers: list[dict]) -> dict:
    graph = {
        'controllers': controllers,
        'functions': {},
        'auth_gates': [],
        'sinks': [],
    }

    func_re = re.compile(
        r'(?:async\s+)?(?:function\s+)?(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:\{|=>)',
    )
    method_re = re.compile(
        r'(?:async\s+)?(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*\{',
    )
    call_re = re.compile(r'(?:\.)?(?P<func>\w+)\s*\([^)]*\)')
    sql_re = re.compile(r'(?:\.query|\.execute|\.raw|knex\()\s*\(', re.IGNORECASE)
    cmd_re = re.compile(r'(?:exec|execSync|spawn|fork)\s*\(', re.IGNORECASE)
    file_re = re.compile(r'(?:readFile|writeFile|createReadStream|createWriteStream|readFileSync)\s*\(', re.IGNORECASE)
    deser_re = re.compile(r'(?:JSON\.parse|eval|vm\.runInNewContext|new Function)\s*\(', re.IGNORECASE)
    redirect_re = re.compile(r'(?:res\.redirect|res\.location|window\.location)\s*\(', re.IGNORECASE)

    sink_patterns = [
        ('sql_injection', sql_re),
        ('command_injection', cmd_re),
        ('path_traversal', file_re),
        ('code_injection', deser_re),
        ('open_redirect', redirect_re),
    ]

    from .controller_scanner import _walk_sources
    for fpath in _walk_sources(repo_path, ('.js', '.ts', '.mjs', '.cjs')):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        relpath = os.path.relpath(fpath, repo_path)

        for pattern in (func_re, method_re):
            for m in pattern.finditer(content):
                func_name = m.group('name')
                args = m.group('args')
                start = m.start()
                line = content[:start].count('\n') + 1
                body = _extract_js_body(content, m.end())
                calls = list(set(call_re.findall(body)))

                sinks = []
                for sink_type, sp in sink_patterns:
                    for sm in sp.finditer(body):
                        sinks.append({
                            'type': sink_type,
                            'code': body[max(0, sm.start()-20):sm.end()+40].strip()[:120],
                            'line': line + body[:sm.start()].count('\n'),
                        })

                graph['functions'][f'{relpath}:{func_name}'] = {
                    'name': func_name,
                    'file': relpath,
                    'line': line,
                    'args': [a.strip().split(':')[0].strip() for a in args.split(',') if a.strip()],
                    'calls': calls,
                    'sinks': sinks,
                }

        for sink_type, sp in sink_patterns:
            for sm in sp.finditer(content):
                graph['sinks'].append({
                    'type': sink_type,
                    'file': relpath,
                    'line': content[:sm.start()].count('\n') + 1,
                    'code': content[max(0, sm.start()-20):sm.end()+60].strip()[:150],
                })

    # Auth gates for Express/NestJS
    auth_re = re.compile(
        r'(?:auth|authenticate|authorize|isAuthenticated|isAuthorized|hasRole|guard)\s*\(?',
        re.IGNORECASE,
    )
    for ctrl in controllers:
        fpath = os.path.join(repo_path, ctrl.get('file', ''))
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        line = ctrl.get('line', 0)
        ctx_lines = content.split('\n')[max(0, line-10):line]
        ctx = '\n'.join(ctx_lines)
        graph['auth_gates'].append({
            'controller': ctrl,
            'type': 'middleware' if auth_re.search(ctx) else 'none',
        })

    return graph


def _extract_js_body(content: str, start_pos: int) -> str:
    """Extract JS/TS function body by tracking brace depth."""
    depth = 0
    started = False
    body_chars = []
    for ch in content[start_pos:]:
        if ch == '{':
            depth += 1
            started = True
        elif ch == '}':
            depth -= 1
            if started and depth == 0:
                break
        if started:
            body_chars.append(ch)
    return ''.join(body_chars)


# ═══════════════════════════════════════════════════════════════════
# Builder registry
# ═══════════════════════════════════════════════════════════════════

def _build_generic(repo_path: str, framework: str, controllers: list[dict]) -> dict:
    return {
        'controllers': controllers,
        'functions': {},
        'auth_gates': [],
        'sinks': [],
    }


_BUILDERS = {
    'python': _build_python,
    'java': _build_java,
    'kotlin': _build_java,
    'javascript': _build_javascript,
}


def render_call_graph_markdown(graph: dict) -> str:
    """Render a call graph as markdown for the AI agent to consume."""
    lines = ["## Application Call Graph\n"]

    lines.append("### REST Controllers\n")
    for c in graph.get('controllers', []):
        auth = next((g for g in graph.get('auth_gates', [])
                     if g.get('controller', {}).get('handler') == c.get('handler')), {})
        auth_type = auth.get('type', 'unknown')
        lines.append(
            f"- `{c['method']} {c['path']}` → **{c['handler']}** "
            f"({c.get('file', '?')}:{c.get('line', '?')}) "
            f"[auth: {auth_type}]"
        )

    lines.append("\n### Call Chains\n")
    for key, func in graph.get('functions', {}).items():
        if func.get('calls'):
            called = ', '.join(f'`{c}()`' for c in func['calls'][:10])
            lines.append(f"- **{func['name']}**() calls: {called}")

    lines.append("\n### Sensitive Sinks\n")
    sinks_by_type = {}
    for s in graph.get('sinks', []):
        sinks_by_type.setdefault(s['type'], []).append(s)
    for stype, items in sinks_by_type.items():
        lines.append(f"\n**{stype}** ({len(items)} occurrences):")
        for s in items[:5]:
            lines.append(f"- `{s['file']}:{s['line']}` — `{s['code'][:100]}`")

    return '\n'.join(lines)
