# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Taint tracker — follows user input from controllers through function calls
to dangerous sinks. Detects unsanitized data flows.

Approach: AST-aware pattern matching + variable propagation across call chains.
For each controller, identify which request parameters flow into which
functions, and whether they reach sinks without sanitization.

Output: list of {source, path: [...], sink, severity, description}
"""

import os
import re


# ── Known sanitizers (framework-agnostic) ──
SANITIZERS = {
    'python': [
        r'(?:int|float|str|bool)\s*\(', r'\.(?:strip|lower|upper|replace|encode)\(', r'escape\(',
        r'(?:sanitize|validate|clean|filter)_?\w*\s*\(', r're\.sub\(', r'\.get\([^)]*,\s*\d+\)',
        r'(?:json|yaml)\.loads?\(', r'Pydantic|pydantic|BaseModel\.', r'@validator',
    ],
    'javascript': [
        r'(?:parseInt|parseFloat|Number|String|Boolean)\s*\(', r'\.(?:trim|toLowerCase|toUpperCase)\(\)\s*',
        r'(?:sanitize|validate|clean|filter)\w*\s*\(', r'joi\.\w+\(', r'zod\.\w+\(', r'class-validator|@Is\w+\(',
    ],
    'java': [
        r'(?:Integer|Long|Double|Float)\.(?:parseInt|parseLong|parseDouble|valueOf)\s*\(', r'\.trim\(\)\s*',
        r'(?:sanitize|validate|clean|escape|filter)\w*\s*\(', r'@Valid\b', r'@NotNull\b', r'@Size\b',
        r'Pattern\.compile\(', r'\.matches\(', r'SecurityUtils\.\w+',
    ],
}


# ── Input sources (per framework) ──
INPUT_SOURCES = {
    ('python', 'fastapi'): [r'request\.query_params', r'request\.body', r'request\.headers',
                             r'Depends\(', r'Body\(', r'Query\(', r'Path\(', r'Header\(', r'Form\('],
    ('python', 'flask'): [r'request\.args', r'request\.form', r'request\.json', r'request\.data',
                          r'request\.headers', r'request\.cookies', r'request\.files'],
    ('python', 'django'): [r'request\.GET', r'request\.POST', r'request\.body', r'request\.META',
                           r'request\.FILES', r'request\.headers'],
    ('java', 'spring'): [r'@RequestParam', r'@RequestBody', r'@PathVariable', r'@RequestHeader',
                         r'@ModelAttribute', r'HttpServletRequest', r'\.getParameter\('],
    ('javascript', 'express'): [r'req\.params', r'req\.query', r'req\.body', r'req\.headers',
                                 r'req\.cookies', r'req\.ip', r'req\.get\('],
    ('javascript', 'nestjs'): [r'@Param\(', r'@Query\(', r'@Body\(', r'@Headers\(', r'@Req\('],
    ('ruby', 'rails'): [r'params\[', r'request\.params', r'request\.body', r'request\.headers'],
    ('php', 'laravel'): [r'\$request->input\(', r'\$request->get\(', r'\$request->post\(',
                         r'\$request->query\(', r'\$request->header\(', r'\$request->all\('],
    ('php', 'symfony'): [r'\$request->get\(', r'\$request->request->get\(', r'\$request->query->get\('],
    ('go', 'go'): [r'r\.URL\.Query\(\)', r'r\.Body', r'r\.Header', r'r\.FormValue\(', r'r\.PostFormValue\(',
                   r'c\.Query\(', r'c\.Param\(', r'c\.PostForm\(', r'c\.Request\.Body'],
}


# ── Dangerous sinks ──
DANGEROUS_SINKS = {
    'python': {
        'sql_injection': [r'(?:\.execute|\.executemany|cursor\.execute|\.raw)\s*\(',
                          r'(?:execute|executemany)\s*\(\s*(?:f["\']|["\']\s*%\s*|["\'].*?\+)'],
        'command_injection': [r'(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|os\.popen|os\.exec\w+|commands\.\w+)\s*\('],
        'code_injection': [r'(?:exec|eval|compile)\s*\(', r'__import__\s*\('],
        'path_traversal': [r'(?:open|read|readlines|write|writelines)\s*\(\s*(?:request\.|f["\']|["\'].*?\+)'],
        'deserialization': [r'(?:pickle\.(?:loads?|load)|yaml\.load\s*\(|marshal\.loads?)\s*\('],
        'ssrf': [r'(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\('],
        'xxe': [r'(?:etree\.parse|lxml\.etree\.parse|xml\.sax\.parse)\s*\('],
    },
    'javascript': {
        'sql_injection': [r'(?:\.query|\.execute|\.raw|knex|\.createQueryBuilder)\s*\(\s*`',
                          r'(?:connection\.query|pool\.query|db\.query)\s*\('],
        'command_injection': [r'(?:exec|execSync|spawn|fork|child_process)\s*\('],
        'code_injection': [r'(?:eval|vm\.runInNewContext|new Function|vm\.Script)\s*\('],
        'path_traversal': [r'(?:readFile|writeFile|readFileSync|createReadStream)\s*\([^)]*\+'],
        'deserialization': [r'(?:javascript-serializer|node-serialize|serialize-to-js)\s*\.'],
        'ssrf': [r'(?:fetch|request|axios|got|node-fetch)\s*\([^)]*req\.'],
        'xss': [r'(?:res\.send|res\.write|res\.end)\s*\([^)]*req\.', r'innerHTML\s*='],
    },
    'java': {
        'sql_injection': [r'(?:executeQuery|executeUpdate|createQuery|createNativeQuery|\.query)\s*\(\s*["\']?\s*\+',
                          r'(?:jdbcTemplate|Statement|PreparedStatement)'],
        'command_injection': [r'(?:Runtime\.exec|ProcessBuilder|ScriptEngine\.eval)\s*\('],
        'path_traversal': [r'(?:FileInputStream|FileReader|Files\.read)\s*\([^)]*\+'],
        'deserialization': [r'(?:ObjectInputStream|readObject|SerializationUtils\.deserialize)\s*\('],
        'xxe': [r'(?:SAXParser|DocumentBuilder|XMLReader|SAXReader)'],
    },
}

# Generic sinks for languages not in the hardcoded lists
_GENERIC_SINKS = {
    'sql_injection': [r'(?:execute|query|raw|exec|execQuery)\s*\(', r'createQuery\s*\('],
    'command_injection': [r'(?:exec|system|popen|spawn|shell)\s*\('],
    'code_injection': [r'(?:eval|exec|compile)\s*\('],
    'path_traversal': [r'(?:open|read|write)\s*\([^)]*\+', r'(?:readFile|writeFile)\s*\([^)]*\+'],
    'deserialization': [r'(?:deserialize|unmarshal|readObject)\s*\('],
}


def track_taint(repo_path: str, language: str, framework: str,
                controllers: list[dict]) -> list[dict]:
    """Main entry point — runs taint analysis on the repo.

    Returns list of taint flows:
      {source_controller, source_param, path: [func1, func2, sink_func],
       sink_type, sink_file, sink_line, severity, description}
    """
    results = []
    exts = _extensions_for(language)
    sanitizers = SANITIZERS.get(language, [])
    sinks = DANGEROUS_SINKS.get(language, _GENERIC_SINKS)
    sources = INPUT_SOURCES.get((language, framework),
                                INPUT_SOURCES.get((language, 'generic'), [r'(?:request|req|params)\.']))

    src_files = _walk_sources(repo_path, exts)

    # Build function call map: {func_name: [called_funcs]}
    func_calls = _build_func_call_map(src_files, language)

    for ctrl in controllers:
        ctrl_file = ctrl.get('file', '')
        ctrl_handler = ctrl.get('handler', '')
        ctrl_line = ctrl.get('line', 0)

        # Resolve controller file path
        full_path = None
        for f in src_files:
            if f.endswith(ctrl_file) or f == os.path.join(repo_path, ctrl_file):
                full_path = f
                break
        if not full_path:
            continue

        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        # Find sources in the handler function
        handler_body = _extract_function_body(content, ctrl_handler, language)
        if not handler_body and ctrl_handler:
            # Try to find the handler function by line number
            lines = content.split('\n')
            if ctrl_line > 0 and ctrl_line < len(lines):
                handler_body = '\n'.join(lines[ctrl_line:ctrl_line + 100])

        if not handler_body and not ctrl_handler:
            # No specific handler — use content around the controller line
            lines = content.split('\n')
            handler_body = '\n'.join(lines[max(0, ctrl_line-1):min(len(lines), ctrl_line + 80)])

        found_sources = []
        # Search both function signature and body for input sources
        search_area = (handler_body or '')
        # Also extract from function params (Query, Body, Path, Header, Form)
        # Get the full function definition line from content
        if ctrl_handler and ctrl_line > 0:
            lines = content.split('\n')
            sig_lines = []
            for i in range(max(0, ctrl_line), min(len(lines), ctrl_line + 5)):
                sig_lines.append(lines[i])
            func_sig = '\n'.join(sig_lines)
            # Extract params that are user inputs
            param_re = re.compile(
                r'(\w+)\s*:\s*\w+\s*=\s*(?:Query|Body|Path|Header|Form|Cookie|Depends)\s*\(',
                re.IGNORECASE,
            )
            for pm in param_re.finditer(func_sig):
                found_sources.append({
                    'pattern': pm.group(1),
                    'line': ctrl_line + func_sig[:pm.start()].count('\n'),
                })

        for src_pattern in sources:
            for m in re.finditer(src_pattern, search_area, re.IGNORECASE):
                found_sources.append({
                    'pattern': m.group(0),
                    'line': ctrl_line + search_area[:m.start()].count('\n'),
                })

        # If no sources found but handler has params, use those
        if not found_sources and ctrl_handler:
            found_sources.append({
                'pattern': f'{ctrl_handler}() params',
                'line': ctrl_line,
            })

        # For each source, trace through call chains to sinks
        for src in found_sources[:5]:  # Limit per controller
            calls_in_handler = _extract_calls(handler_body, language)

            for call in calls_in_handler:
                # Follow the call chain
                chain = [ctrl_handler or f'{ctrl["method"]} {ctrl["path"]}']
                visited = set()
                sinks_found = _trace_to_sink(
                    call, func_calls, sinks, sanitizers, repo_path,
                    src_files, chain, visited, depth=0, max_depth=3,
                )
                for sink_info in sinks_found:
                    results.append({
                        'source_controller': f"{ctrl['method']} {ctrl['path']}",
                        'source_handler': ctrl_handler,
                        'source_file': ctrl_file,
                        'source_param': src['pattern'],
                        'flow_path': ' → '.join(chain + [sink_info['func']]),
                        'sink_type': sink_info['type'],
                        'sink_file': sink_info.get('file', ctrl_file),
                        'sink_line': sink_info['line'],
                        'severity': sink_info['severity'],
                        'description': sink_info['description'],
                        'has_sanitizer': sink_info.get('has_sanitizer', False),
                    })

    return results


def _trace_to_sink(func_name, func_calls, sinks, sanitizers, repo_path,
                   src_files, chain, visited, depth, max_depth):
    """Recursively trace a function call to dangerous sinks."""
    if depth > max_depth or func_name in visited:
        return []
    visited.add(func_name)

    # Fast path: check if the call itself is a known dangerous function
    results = _check_direct_sink(func_name, sinks)
    if results:
        chain.append(func_name)
        return results

    chain.append(func_name)

    # Search source files for this function's body containing sinks
    for sink_type, patterns in sinks.items():
        for sink_file in src_files:
            try:
                with open(sink_file, 'r', encoding='utf-8', errors='replace') as fh:
                    content = fh.read()
            except Exception:
                continue
            func_body = _extract_function_body(content, func_name, 'python')
            if not func_body:
                func_pattern = re.compile(
                    rf'(?:def|function|async\s+function|public|private|protected)\s+'
                    rf'{re.escape(func_name)}\s*\(',
                )
                fm = func_pattern.search(content)
                if fm:
                    body_start = fm.end()
                    lines = content[body_start:].split('\n')
                    func_body = '\n'.join(lines[:80])

            if not func_body:
                continue

            for sp in patterns:
                for m in re.finditer(sp, func_body, re.IGNORECASE):
                    if _has_sanitizer_before_sink(func_body, m.start(), sanitizers):
                        continue
                    line = content[:content.find(func_body) + m.start()].count('\n') + 1 if func_body else 0
                    results.append({
                        'type': sink_type,
                        'func': func_name,
                        'file': os.path.relpath(sink_file, repo_path),
                        'line': line,
                        'severity': _severity_for(sink_type),
                        'description': _desc_for(sink_type, func_name),
                    })
                    break

    # Recurse into called functions
    called = func_calls.get(func_name, [])
    for child in called:
        results.extend(
            _trace_to_sink(child, func_calls, sinks, sanitizers, repo_path,
                          src_files, list(chain), visited, depth + 1, max_depth)
        )

    return results


def _check_direct_sink(func_name: str, sinks: dict) -> list:
    """Check if func_name directly matches a dangerous function/method."""
    dangerous = {
        'execute': 'sql_injection',
        'executemany': 'sql_injection',
        'exec': 'command_injection',
        'eval': 'code_injection',
        'loads': 'deserialization',
        'load': 'deserialization',
        'subprocess.run': 'command_injection',
        'subprocess.call': 'command_injection',
        'subprocess.Popen': 'command_injection',
        'os.system': 'command_injection',
        'os.popen': 'command_injection',
        'pickle.loads': 'deserialization',
        'pickle.load': 'deserialization',
        'yaml.load': 'deserialization',
        'requests.get': 'ssrf',
        'requests.post': 'ssrf',
        'httpx.get': 'ssrf',
        'httpx.post': 'ssrf',
        'urllib.request.urlopen': 'ssrf',
    }
    # Check if func_name or combined parent.func matches
    sink_type = dangerous.get(func_name)
    if not sink_type:
        return []

    return [{
        'type': sink_type,
        'func': func_name,
        'file': '',
        'line': 0,
        'severity': _severity_for(sink_type),
        'description': _desc_for(sink_type, func_name),
    }]


def _has_sanitizer_before_sink(body: str, sink_pos: int, sanitizers: list) -> bool:
    """Check if the code before the sink has sanitization."""
    before = body[max(0, sink_pos - 500):sink_pos]
    for san_pattern in sanitizers:
        if re.search(san_pattern, before, re.IGNORECASE):
            return True
    return False


def _build_func_call_map(src_files: list, language: str) -> dict:
    """Build a map of function → called functions across the codebase."""
    call_map = {}
    func_def_re = _func_def_pattern(language)
    call_re = _call_pattern(language)

    for fpath in src_files:
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        # Find function definitions
        for m in func_def_re.finditer(content):
            func_name = m.group('name')
            body = _extract_function_body(content, func_name, language) or content[m.end():m.end()+2000]
            calls = list(set(call_re.findall(body)))
            call_map[func_name] = calls

    return call_map


def _extract_function_body(content: str, func_name: str, language: str) -> str | None:
    """Extract a function's body from source code by name."""
    if not func_name:
        return None

    patterns = [
        rf'(?:async\s+)?def\s+{re.escape(func_name)}\s*\([^)]*\)(?:\s*->\s*\S+)?\s*:',
        rf'(?:async\s+)?function\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{',
        rf'(?:public|private|protected)\s+(?:\w+(?:<[^>]+>)?\s+)?{re.escape(func_name)}\s*\([^)]*\)\s*(?:\{{|throws)',
        rf'func\s+{re.escape(func_name)}\s*\([^)]*\)',
        rf'def\s+{re.escape(func_name)}\s*\([^)]*\)',
    ]

    for pattern in patterns:
        m = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
        if m:
            body_start = m.end()
            return _extract_body_by_brace(content, body_start, language)

    return None


def _extract_body_by_brace(content: str, start: int, language: str) -> str:
    """Extract function body using brace/indentation tracking."""
    body = content[start:]
    if language in ('java', 'javascript', 'go', 'kotlin', 'scala', 'csharp', 'swift'):
        return _extract_brace_body(body)
    return _extract_indent_body(body)


def _extract_brace_body(text: str) -> str:
    depth = 0
    started = False
    result = []
    for ch in text:
        if ch == '{':
            depth += 1
            started = True
        elif ch == '}':
            depth -= 1
            if started and depth == 0:
                break
        if started:
            result.append(ch)
    return ''.join(result)


def _extract_indent_body(text: str) -> str:
    lines = text.split('\n')
    body = []
    in_body = False
    base_indent = None
    for line in lines:
        stripped = line.strip()
        if not in_body:
            if stripped and not stripped.startswith('#'):
                in_body = True
                base_indent = len(line) - len(line.lstrip())
                if stripped:
                    body.append(line)
            continue
        if not stripped:
            body.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent and stripped and not stripped.startswith('#'):
            break
        body.append(line)
    return '\n'.join(body)


def _extract_calls(body: str, language: str) -> list:
    """Extract function call names from a body of code."""
    simple_re = re.compile(r'(?:self\.)?(\w+)\s*\(')
    qualified_re = re.compile(r'(\w+)\.(\w+)\s*\(')
    keywords = {
        'if', 'for', 'while', 'return', 'print', 'len', 'str', 'int',
        'list', 'dict', 'set', 'tuple', 'type', 'isinstance', 'hasattr',
        'getattr', 'setattr', 'super', 'range', 'enumerate',
    }
    calls = set()
    for m in simple_re.finditer(body):
        g = m.group(1)
        if g and len(g) > 1 and not g.startswith('_') and g not in keywords:
            calls.add(g)
    for m in qualified_re.finditer(body):
        a, b = m.groups()
        if a and len(a) > 1: calls.add(a)
        if b and len(b) > 1: calls.add(b)
        if a and b:
            calls.add(f'{a}.{b}')
    return list(calls)


# ── Helpers ──

def _walk_sources(repo_path: str, extensions: tuple) -> list:
    from purpleteam.controller_scanner import _walk_sources as _w
    return _w(repo_path, extensions)


def _extensions_for(language: str) -> tuple:
    return {
        'python': ('.py',), 'java': ('.java',), 'kotlin': ('.kt',),
        'javascript': ('.js', '.ts', '.mjs', '.cjs'),
        'go': ('.go',), 'ruby': ('.rb',), 'php': ('.php',),
        'csharp': ('.cs',), 'swift': ('.swift',), 'scala': ('.scala',),
        'rust': ('.rs',),
    }.get(language, ('.py', '.java', '.js', '.ts', '.go', '.php'))


def _func_def_pattern(language: str) -> re.Pattern:
    patterns = {
        'python': re.compile(r'(?:async\s+)?def\s+(?P<name>\w+)\s*\([^)]*\)', re.MULTILINE),
        'javascript': re.compile(r'(?:async\s+)?(?:function\s+)?(?P<name>\w+)\s*\([^)]*\)\s*(?:\{|=>)', re.MULTILINE),
        'java': re.compile(r'(?:public|private|protected)\s+(?:\w+(?:<[^>]+>)?\s+)?(?P<name>\w+)\s*\([^)]*\)', re.MULTILINE),
        'go': re.compile(r'func\s+(?:\(\w+\s+\*?\w+\)\s+)?(?P<name>\w+)\s*\([^)]*\)', re.MULTILINE),
        'ruby': re.compile(r'def\s+(?P<name>\w+)[!?]?\s*(?:\([^)]*\))?', re.MULTILINE),
        'php': re.compile(r'(?:public|private|protected\s+)?function\s+(?P<name>\w+)\s*\([^)]*\)', re.MULTILINE),
    }
    return patterns.get(language, patterns['python'])


def _call_pattern(language: str) -> re.Pattern:
    return re.compile(r'(?:\w+\.)?(\w+)\s*\(', re.MULTILINE)


def _severity_for(sink_type: str) -> str:
    return {
        'sql_injection': 'critical', 'command_injection': 'critical',
        'code_injection': 'critical', 'deserialization': 'high',
        'path_traversal': 'high', 'ssrf': 'high', 'xxe': 'high',
        'xss': 'medium',
    }.get(sink_type, 'medium')


def _desc_for(sink_type: str, func_name: str) -> str:
    descs = {
        'sql_injection': f"User input flows to database query in {func_name}() without sanitization",
        'command_injection': f"User input flows to command execution in {func_name}()",
        'code_injection': f"User input flows to code evaluation in {func_name}()",
        'path_traversal': f"User input flows to file operation in {func_name}() without path validation",
        'deserialization': f"User input flows to deserialization in {func_name}() — potential RCE",
        'ssrf': f"User input flows to HTTP request in {func_name}() — SSRF risk",
        'xxe': f"User input flows to XML parser in {func_name}() — XXE risk",
        'xss': f"User input flows to HTML output in {func_name}() without escaping",
    }
    return descs.get(sink_type, f"User input reaches dangerous sink in {func_name}()")
