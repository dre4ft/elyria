# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
REST controller detection — extracts the attack surface from source code.

For each supported framework, detects:
  - HTTP method + path
  - Handler function name
  - File path + line number
  - Path parameters (e.g. /users/{id})
  - Query parameters (from handler signature or explicit definition)

Returns a list of dicts:
  {method, path, handler, file, line, params, framework}
"""

import os
import re


def detect_controllers(repo_path: str, language: str, framework: str) -> list[dict]:
    """Main entry point — dispatches to framework-specific detectors."""
    detectors = {
        ("python", "fastapi"): _detect_fastapi,
        ("python", "flask"): _detect_flask,
        ("python", "django"): _detect_django,
        ("java", "spring"): _detect_spring,
        ("javascript", "express"): _detect_express,
        ("javascript", "nestjs"): _detect_nestjs,
        ("go", "go"): _detect_go,
        ("ruby", "rails"): _detect_rails,
        ("php", "laravel"): _detect_laravel,
        ("php", "symfony"): _detect_symfony,
    }
    detector = detectors.get((language, framework)) or detectors.get((language, "generic"))
    if not detector:
        return _detect_generic(repo_path, language)
    return detector(repo_path)


def _walk_sources(repo_path: str, extensions: tuple) -> list[str]:
    """Walk repo and return list of source files matching extensions."""
    files = []
    skip_dirs = {'.git', '__pycache__', 'node_modules', 'venv', '.venv', 'vendor',
                 '.idea', '.vscode', 'dist', 'build', 'target', '.next', 'out',
                 'migrations', 'tests', '__tests__', 'test', 'spec', 'bin', 'obj'}
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith('.')]
        for f in filenames:
            if f.endswith(extensions):
                files.append(os.path.join(root, f))
    return files


# ═══════════════════════════════════════════════════════════════════
# Python — FastAPI
# ═══════════════════════════════════════════════════════════════════

def _detect_fastapi(repo_path: str) -> list[dict]:
    """Detect FastAPI endpoints: @router.get('/path'), @app.post('/path'), etc."""
    endpoints = []
    route_re = re.compile(
        r'@(?:\w+\.)?(?P<method>get|post|put|delete|patch|head|options|trace)\s*\('
        r'[\'\"](?P<path>[^\'\"]+)[\'\"]',
        re.IGNORECASE,
    )
    param_re = re.compile(r'\{(\w+)\}')
    handler_re = re.compile(
        r'(?:async\s+)?def\s+(?P<handler>\w+)\s*\(',
    )

    for fpath in _walk_sources(repo_path, ('.py',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        for m in route_re.finditer(content):
            path = m.group('path')
            params = param_re.findall(path)
            line = content[:m.start()].count('\n') + 1

            # Find handler: the next 'def' after the route decorator
            handler = ''
            after = content[m.end():m.end() + 500]
            hm = handler_re.search(after)
            if hm:
                handler = hm.group('handler')

            endpoints.append({
                'method': m.group('method').upper(),
                'path': path,
                'handler': handler,
                'file': os.path.relpath(fpath, repo_path),
                'line': line,
                'params': params,
                'framework': 'fastapi',
            })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# Python — Flask
# ═══════════════════════════════════════════════════════════════════

def _detect_flask(repo_path: str) -> list[dict]:
    """Detect Flask endpoints: @app.route('/path', methods=[...]), @bp.route(...)"""
    endpoints = []
    route_re = re.compile(
        r'@(?P<app>\w+)\.route\s*\(\s*[\'\"](?P<path>[^\'\"]+)[\'\"]'
        r'(?:\s*,\s*methods\s*=\s*\[(?P<methods>[^\]]+)\])?',
        re.IGNORECASE,
    )
    param_re = re.compile(r'<(\w+:)?(\w+)>')
    handler_re = re.compile(
        r'@\w+\.route\([^)]+\)\s*\n\s*def\s+(?P<handler>\w+)',
    )

    for fpath in _walk_sources(repo_path, ('.py',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        for m in route_re.finditer(content):
            path = m.group('path')
            methods_str = m.group('methods')
            if methods_str:
                methods = [x.strip().strip("'\"") for x in methods_str.split(',')]
            else:
                methods = ['GET']
            params = [p.split(':')[-1] for p in param_re.findall(path)]
            line = content[:m.start()].count('\n') + 1

            handler = ''
            handler_m = handler_re.search(content, m.end())
            if handler_m:
                handler = handler_m.group('handler')

            for method in methods:
                endpoints.append({
                    'method': method.upper(),
                    'path': path,
                    'handler': handler,
                    'file': os.path.relpath(fpath, repo_path),
                    'line': line,
                    'params': params,
                    'framework': 'flask',
                })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# Python — Django
# ═══════════════════════════════════════════════════════════════════

def _detect_django(repo_path: str) -> list[dict]:
    """Detect Django URL patterns from urls.py files."""
    endpoints = []
    path_re = re.compile(
        r'(?:path|re_path|url)\s*\(\s*[\'\"](?P<path>[^\'\"]+)[\'\"](?:\s*,\s*(?P<view>[\w.]+))?',
    )
    drf_viewset_re = re.compile(r"class\s+(?P<name>\w+)\s*\([^)]*ViewSet[^)]*\)", re.IGNORECASE)
    drf_action_re = re.compile(
        r'@action\s*\([^)]*methods\s*=\s*\[(?P<methods>[^\]]+)\][^)]*detail\s*=\s*(?P<detail>True|False)[^)]*\)\s*\n\s*def\s+(?P<handler>\w+)',
    )

    for fpath in _walk_sources(repo_path, ('.py',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        # URL patterns
        for m in path_re.finditer(content):
            path = m.group('path') or ''
            view = m.group('view') or ''
            line = content[:m.start()].count('\n') + 1
            endpoints.append({
                'method': '*',
                'path': path,
                'handler': view,
                'file': os.path.relpath(fpath, repo_path),
                'line': line,
                'params': [],
                'framework': 'django',
            })

        # DRF ViewSet actions
        for m in drf_action_re.finditer(content):
            methods = [x.strip().strip("'\"") for x in m.group('methods').split(',')]
            line = content[:m.start()].count('\n') + 1
            for method in methods:
                endpoints.append({
                    'method': method.upper(),
                    'path': '',
                    'handler': m.group('handler'),
                    'file': os.path.relpath(fpath, repo_path),
                    'line': line,
                    'params': [],
                    'framework': 'django-drf',
                })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# Java — Spring Boot
# ═══════════════════════════════════════════════════════════════════

def _detect_spring(repo_path: str) -> list[dict]:
    """Detect Spring Boot REST controllers."""
    endpoints = []
    mapping_re = re.compile(
        r'@(?P<type>GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)'
        r'\s*\((?:[^)]*value\s*=\s*[\'\"](?P<path>[^\'\"]+)[\'\"][^)]*|[\'\"](?P<path2>[^\'\"]+)[\'\"][^)]*)\)',
        re.IGNORECASE,
    )
    controller_re = re.compile(
        r'@(?:Rest)?Controller\s*\(?\s*(?:[\'\"](?P<base>[^\'\"]+)[\'\"])?\s*\)?',
        re.IGNORECASE,
    )
    method_re = re.compile(
        r'(?:public|private|protected)\s+\w+\s+(?P<handler>\w+)\s*\([^)]*\)\s*(?:\{|throws)',
    )
    path_var_re = re.compile(r'\{(\w+)\}')

    for fpath in _walk_sources(repo_path, ('.java',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        # Find controller base path
        base_path = ''
        ctrl_m = controller_re.search(content)
        if ctrl_m and ctrl_m.group('base'):
            base_path = ctrl_m.group('base').strip('/')

        for m in mapping_re.finditer(content):
            path = (m.group('path') or m.group('path2') or '').strip('/')
            full_path = ('/' + base_path + '/' + path).replace('//', '/') if path else ('/' + base_path if base_path else '/')
            params = path_var_re.findall(path)
            line = content[:m.start()].count('\n') + 1

            handler = ''
            handler_m = method_re.search(content, m.end())
            if handler_m:
                handler = handler_m.group('handler')

            endpoints.append({
                'method': m.group('type').upper().replace('MAPPING', ''),
                'path': full_path,
                'handler': handler,
                'file': os.path.relpath(fpath, repo_path),
                'line': line,
                'params': params,
                'framework': 'spring',
            })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# JavaScript — Express
# ═══════════════════════════════════════════════════════════════════

def _detect_express(repo_path: str) -> list[dict]:
    """Detect Express.js endpoints."""
    endpoints = []
    route_re = re.compile(
        r'(?P<router>\w+)\.(?P<method>get|post|put|delete|patch|head|options|all)\s*\(?\s*'
        r'[\'\"](?P<path>[^\'\"]+)[\'\"]',
        re.IGNORECASE,
    )
    param_re = re.compile(r':(\w+)')

    for fpath in _walk_sources(repo_path, ('.js', '.ts', '.mjs', '.cjs')):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        for m in route_re.finditer(content):
            path = m.group('path')
            params = param_re.findall(path)
            line = content[:m.start()].count('\n') + 1
            endpoints.append({
                'method': m.group('method').upper(),
                'path': path,
                'handler': '',
                'file': os.path.relpath(fpath, repo_path),
                'line': line,
                'params': params,
                'framework': 'express',
            })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# JavaScript/TypeScript — NestJS
# ═══════════════════════════════════════════════════════════════════

def _detect_nestjs(repo_path: str) -> list[dict]:
    """Detect NestJS controllers with decorators."""
    endpoints = []
    ctrl_re = re.compile(r"@Controller\s*\(\s*['\"](?P<base>[^'\"]*)['\"]\s*\)", re.IGNORECASE)
    method_re = re.compile(
        r"@(?P<type>Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*['\"](?P<path>[^'\"]*)['\"]",
        re.IGNORECASE,
    )
    handler_re = re.compile(
        r"(?:async\s+)?(?P<handler>\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{",
    )
    param_re = re.compile(r':(\w+)')

    for fpath in _walk_sources(repo_path, ('.ts', '.js')):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        base_path = ''
        ctrl_m = ctrl_re.search(content)
        if ctrl_m:
            base_path = ctrl_m.group('base').strip('/')

        for m in method_re.finditer(content):
            path = m.group('path').strip('/')
            full_path = ('/' + base_path + '/' + path).replace('//', '/') if path else ('/' + base_path if base_path else '/')
            params = param_re.findall(path)
            line = content[:m.start()].count('\n') + 1

            handler = ''
            handler_m = handler_re.search(content, m.end())
            if handler_m:
                handler = handler_m.group('handler')

            endpoints.append({
                'method': m.group('type').upper(),
                'path': full_path,
                'handler': handler,
                'file': os.path.relpath(fpath, repo_path),
                'line': line,
                'params': params,
                'framework': 'nestjs',
            })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# Go
# ═══════════════════════════════════════════════════════════════════

def _detect_go(repo_path: str) -> list[dict]:
    """Detect Go endpoints for chi, gin, echo, net/http."""
    endpoints = []
    route_re = re.compile(
        r'(?P<router>\w+)\.(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HandleFunc|Handle)\s*\(\s*'
        r'[\'\"](?P<path>[^\'\"]+)[\'\"]',
    )
    param_re = re.compile(r'\{(?:(\w+)[:\s]?)+\}')
    gin_param_re = re.compile(r':(\w+)')

    for fpath in _walk_sources(repo_path, ('.go',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        for m in route_re.finditer(content):
            method = m.group('method')
            if method in ('HandleFunc', 'Handle'):
                method = '*'
            path = m.group('path')
            params = param_re.findall(path) or gin_param_re.findall(path)
            line = content[:m.start()].count('\n') + 1
            endpoints.append({
                'method': method,
                'path': path,
                'handler': '',
                'file': os.path.relpath(fpath, repo_path),
                'line': line,
                'params': [p.split(':')[-1].strip() if ':' in p else p for p in params],
                'framework': 'go',
            })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# Ruby — Rails
# ═══════════════════════════════════════════════════════════════════

def _detect_rails(repo_path: str) -> list[dict]:
    """Detect Rails routes from routes.rb."""
    endpoints = []
    rest_re = re.compile(r'resources\s+:(?P<resource>\w+)')
    route_re = re.compile(
        r'(?P<method>get|post|put|patch|delete)\s+[\'\"](?P<path>[^\'\"]+)[\'\"]\s*(?:=>|,)\s*[\'\"](?P<handler>[^\'\"]+)[\'\"]',
        re.IGNORECASE,
    )
    controller_re = re.compile(r'controller\s*:\s*[\'\"](?P<ctrl>[^\'\"]+)[\'\"]')

    for fpath in _walk_sources(repo_path, ('.rb',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        # REST resources
        for m in rest_re.finditer(content):
            resource = m.group('resource')
            line = content[:m.start()].count('\n') + 1
            for http_method, action in [
                ('GET', 'index'), ('GET', 'show'), ('POST', 'create'),
                ('PUT', 'update'), ('PATCH', 'update'), ('DELETE', 'destroy'),
            ]:
                path = f"/{resource}" if action in ('index', 'create') else f"/{resource}/:id"
                endpoints.append({
                    'method': http_method,
                    'path': path,
                    'handler': f"{resource}#{action}",
                    'file': os.path.relpath(fpath, repo_path),
                    'line': line,
                    'params': ['id'] if ':id' in path else [],
                    'framework': 'rails',
                })

        # Explicit routes
        for m in route_re.finditer(content):
            line = content[:m.start()].count('\n') + 1
            endpoints.append({
                'method': m.group('method').upper(),
                'path': m.group('path'),
                'handler': m.group('handler'),
                'file': os.path.relpath(fpath, repo_path),
                'line': line,
                'params': [],
                'framework': 'rails',
            })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# PHP — Laravel
# ═══════════════════════════════════════════════════════════════════

def _detect_laravel(repo_path: str) -> list[dict]:
    """Detect Laravel routes."""
    endpoints = []
    route_re = re.compile(
        r"Route::(?P<method>get|post|put|patch|delete|options|any|match)\s*\(\s*"
        r"['\"](?P<path>[^'\"]+)['\"]\s*,\s*\[(?P<ctrl>[^\]]+)\]",
        re.IGNORECASE,
    )
    resource_re = re.compile(
        r"Route::(?:api)?Resource\s*\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*(?P<ctrl>\w+::class)",
        re.IGNORECASE,
    )
    param_re = re.compile(r'\{(\w+)\}')

    for fpath in _walk_sources(repo_path, ('.php',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        for m in route_re.finditer(content):
            path = m.group('path')
            params = param_re.findall(path)
            line = content[:m.start()].count('\n') + 1
            endpoints.append({
                'method': m.group('method').upper(),
                'path': path,
                'handler': m.group('ctrl'),
                'file': os.path.relpath(fpath, repo_path),
                'line': line,
                'params': params,
                'framework': 'laravel',
            })

        for m in resource_re.finditer(content):
            resource = m.group('path').strip('/')
            line = content[:m.start()].count('\n') + 1
            for http_method, action in [
                ('GET', 'index'), ('GET', 'show'), ('POST', 'store'),
                ('PUT', 'update'), ('DELETE', 'destroy'),
            ]:
                path = f"/{resource}" if action in ('index', 'store') else f"/{resource}/{{id}}"
                endpoints.append({
                    'method': http_method,
                    'path': path,
                    'handler': f"{m.group('ctrl')}@{action}",
                    'file': os.path.relpath(fpath, repo_path),
                    'line': line,
                    'params': ['id'] if '{id}' in path else [],
                    'framework': 'laravel',
                })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# PHP — Symfony
# ═══════════════════════════════════════════════════════════════════

def _detect_symfony(repo_path: str) -> list[dict]:
    """Detect Symfony routes from attributes and annotations."""
    endpoints = []
    attr_re = re.compile(
        r"#\[Route\s*\(\s*['\"](?P<path>[^'\"]+)['\"]"
        r"(?:\s*,\s*(?:name|methods):\s*\[(?P<methods>[^\]]+)\])?\s*\)",
        re.IGNORECASE,
    )
    ann_re = re.compile(
        r"@Route\s*\(\s*['\"](?P<path>[^'\"]+)['\"]"
        r"(?:\s*,\s*name:\s*['\"][^'\"]+['\"]\s*,?\s*(?:methods=\{(?P<methods>[^}]+)\})?)?\)",
        re.IGNORECASE,
    )
    handler_re = re.compile(
        r"(?:public|protected|private)\s+function\s+(?P<handler>\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{",
    )
    param_re = re.compile(r'\{(\w+)\}')

    for fpath in _walk_sources(repo_path, ('.php',)):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        for pattern in (attr_re, ann_re):
            for m in pattern.finditer(content):
                path = m.group('path')
                methods_str = m.group('methods')
                methods = [x.strip().strip("'\"") for x in (methods_str or 'GET').split(',')]
                params = param_re.findall(path)
                line = content[:m.start()].count('\n') + 1

                handler = ''
                handler_m = handler_re.search(content, m.end())
                if handler_m:
                    handler = handler_m.group('handler')

                for method in methods:
                    endpoints.append({
                        'method': method.upper(),
                        'path': path,
                        'handler': handler,
                        'file': os.path.relpath(fpath, repo_path),
                        'line': line,
                        'params': params,
                        'framework': 'symfony',
                    })

    return endpoints


# ═══════════════════════════════════════════════════════════════════
# Generic — heuristic detection for unknown frameworks
# ═══════════════════════════════════════════════════════════════════

def _detect_generic(repo_path: str, language: str) -> list[dict]:
    """Heuristic detection for unknown frameworks."""
    endpoints = []
    generic_route_re = re.compile(
        r'(?:route|endpoint|path)\s*[=:]\s*[\'\"](/[\w/\-_{}]*)[\'\"]',
        re.IGNORECASE,
    )

    exts = {
        'python': ('.py',), 'java': ('.java',), 'javascript': ('.js', '.ts', '.mjs'),
        'go': ('.go',), 'ruby': ('.rb',), 'php': ('.php',),
        'kotlin': ('.kt',), 'csharp': ('.cs',), 'swift': ('.swift',),
        'scala': ('.scala',), 'rust': ('.rs',),
    }.get(language, ('.py', '.java', '.js', '.ts', '.go', '.rb', '.php'))

    for fpath in _walk_sources(repo_path, exts):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except Exception:
            continue

        for m in generic_route_re.finditer(content):
            line = content[:m.start()].count('\n') + 1
            endpoints.append({
                'method': '*',
                'path': m.group(1),
                'handler': '',
                'file': os.path.relpath(fpath, repo_path),
                'line': line,
                'params': [],
                'framework': 'generic',
            })

    return endpoints
