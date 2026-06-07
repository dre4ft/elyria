# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Repository manager — clone/fetch from GitHub, GitLab, Bitbucket with auth,
manage local repos, enforce 200 MB per user storage limit.
"""

import os
import shlex
import shutil
import subprocess
import tempfile
from core.logging import get_logger
from purpleteam.database import get_user_repo_usage, register_repo, delete_repo_by_path

_log = get_logger("purpleteam.repo")

STORAGE_BASE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "purpleteam_repos")
MAX_STORAGE_PER_USER = 200 * 1024 * 1024  # 200 MB


def _ensure_storage_dir(user_id):
    path = os.path.join(STORAGE_BASE, user_id)
    os.makedirs(path, exist_ok=True)
    return path


def _check_storage_limit(user_id, additional_bytes):
    current = get_user_repo_usage(user_id)
    if current + additional_bytes > MAX_STORAGE_PER_USER:
        raise StorageLimitExceeded(
            f"Storage limit exceeded: {current / 1024 / 1024:.1f} MB used + "
            f"{additional_bytes / 1024 / 1024:.1f} MB would exceed "
            f"{MAX_STORAGE_PER_USER / 1024 / 1024:.0f} MB limit"
        )


def _get_dir_size(path):
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def _build_auth_url(repo_url, auth_type, auth_key):
    """Build authenticated URL for git clone."""
    if not auth_key or not auth_type:
        return repo_url

    if auth_type == "bearer" or auth_type == "token":
        if "github.com" in repo_url:
            return repo_url.replace("https://", f"https://x-access-token:{auth_key}@")
        elif "gitlab.com" in repo_url:
            return repo_url.replace("https://", f"https://oauth2:{auth_key}@")
        elif "bitbucket.org" in repo_url:
            return repo_url.replace("https://", f"https://x-token-auth:{auth_key}@")
        else:
            return repo_url.replace("https://", f"https://token:{auth_key}@")
    elif auth_type == "api_key":
        if "github.com" in repo_url:
            return repo_url.replace("https://", f"https://{auth_key}:x-oauth-basic@")
        return repo_url.replace("https://", f"https://api:{auth_key}@")
    return repo_url


def _docker_available():
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def clone_repo(repo_url, user_id, auth_type="", auth_key="", branch="main"):
    """Clone a remote repository. Uses Docker sandbox if available, else direct clone.
    In both cases the .git directory is removed after clone and files are purged after scan."""
    user_dir = _ensure_storage_dir(user_id)
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "") or "repo"
    dest = os.path.join(user_dir, repo_name)

    if os.path.exists(dest):
        shutil.rmtree(dest)

    auth_url = _build_auth_url(repo_url, auth_type, auth_key)

    if _docker_available():
        return _clone_via_sandbox(auth_url, repo_url, auth_key, branch, user_id, dest)
    return _clone_direct(auth_url, repo_url, auth_key, branch, user_id, dest)


def _clone_via_sandbox(auth_url, repo_url, auth_key, branch, user_id, dest):
    """Clone inside a Docker sandbox, extract sources, destroy container."""
    from sandbox.manager import SandboxManager

    branch_flag = f"--branch {shlex.quote(branch)}" if branch else ""
    _log.info(f"Cloning {repo_url} inside sandbox for user {user_id}")

    mgr = SandboxManager()
    sandbox = mgr.spawn()
    sandbox_id = sandbox.container_id

    try:
        clone_cmd = f"git clone --depth 1 {branch_flag} {shlex.quote(auth_url)} /tmp/repo 2>&1"
        result = sandbox.exec(clone_cmd, timeout_ms=120_000)
        if result["exit_code"] != 0:
            err = result.get("stderr", "") or result.get("stdout", "")
            if auth_key:
                err = err.replace(auth_key, "***")
            raise CloneFailed(f"Clone failed: {err[:500]}")

        sandbox.exec("rm -rf /tmp/repo/.git", timeout_ms=10_000)

        subprocess.run(
            ["docker", "cp", f"{sandbox_id}:/tmp/repo/.", dest],
            capture_output=True, timeout=30,
        )
    finally:
        sandbox.destroy()
        _log.info(f"Sandbox {sandbox_id} destroyed")

    return _finalize_clone(dest, repo_url, user_id)


def _clone_direct(auth_url, repo_url, auth_key, branch, user_id, dest):
    """Direct git clone — used when Docker is unavailable."""
    branch_flag = ["--branch", branch] if branch else []

    _log.info(f"Cloning {repo_url} (branch={branch}) directly for user {user_id}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1"] + branch_flag + [auth_url, dest],
        capture_output=True, text=True, timeout=120,
    )

    if result.returncode != 0:
        err = result.stderr.replace(auth_key, "***") if auth_key else result.stderr
        raise CloneFailed(f"Clone failed: {err[:500]}")

    # Remove .git to avoid leaking credentials/history
    git_dir = os.path.join(dest, ".git")
    if os.path.exists(git_dir):
        shutil.rmtree(git_dir)

    return _finalize_clone(dest, repo_url, user_id)


def _finalize_clone(dest, repo_url, user_id):
    """Common post-clone steps."""
    if not os.path.isdir(dest) or not os.listdir(dest):
        raise CloneFailed("Clone produced empty directory")

    size = _get_dir_size(dest)
    try:
        _check_storage_limit(user_id, size)
    except StorageLimitExceeded:
        shutil.rmtree(dest)
        raise

    source = "github"
    if "gitlab" in repo_url:
        source = "gitlab"
    elif "bitbucket" in repo_url:
        source = "bitbucket"

    register_repo(user_id, source, dest, repo_url, size)
    _log.info(f"Cloned {repo_url} → {dest} ({size / 1024 / 1024:.1f} MB)")
    return dest


def store_local_repo(source_path, user_id):
    """Copy a local directory as a repo. Returns the local path."""
    if not os.path.isdir(source_path):
        raise ValueError(f"Not a directory: {source_path}")

    user_dir = _ensure_storage_dir(user_id)
    repo_name = os.path.basename(source_path.rstrip("/")) or "repo"
    dest = os.path.join(user_dir, repo_name)

    if os.path.exists(dest):
        shutil.rmtree(dest)

    # Estimate size first (walk without copying)
    size = _get_dir_size(source_path)
    _check_storage_limit(user_id, size)

    shutil.copytree(source_path, dest)
    register_repo(user_id, "local", dest, "", size)
    _log.info(f"Stored local repo {source_path} → {dest} ({size / 1024 / 1024:.1f} MB)")
    return dest


def store_uploaded_zip(zip_data, filename, user_id):
    """Extract an uploaded zip file as a local repo. Returns the local path."""
    user_dir = _ensure_storage_dir(user_id)
    repo_name = filename.replace(".zip", "").replace(".tar.gz", "").replace(".tgz", "") or "repo"
    dest = os.path.join(user_dir, repo_name)

    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest, exist_ok=True)

    tmp_path = os.path.join(user_dir, f".tmp_{repo_name}.zip")
    with open(tmp_path, "wb") as f:
        f.write(zip_data)

    try:
        import zipfile
        if zipfile.is_zipfile(tmp_path):
            with zipfile.ZipFile(tmp_path, "r") as zf:
                zf.extractall(dest)
        else:
            shutil.rmtree(dest)
            raise ValueError("Uploaded file is not a valid zip archive")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    size = _get_dir_size(dest)
    try:
        _check_storage_limit(user_id, size)
    except StorageLimitExceeded:
        shutil.rmtree(dest)
        raise

    register_repo(user_id, "local", dest, "", size)
    _log.info(f"Extracted uploaded repo → {dest} ({size / 1024 / 1024:.1f} MB)")
    return dest


def cleanup_repo(repo_path):
    """Delete a repo and its tracking record."""
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)
    delete_repo_by_path(repo_path)
    _log.info(f"Cleaned up repo: {repo_path}")


def list_repo_files(repo_path, max_files=200):
    """List source files in a repo, filtering out binary/dependency dirs."""
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", "target",
                 "build", "dist", ".gradle", ".idea", ".mvn", "bin", "obj",
                 ".next", ".nuxt", ".output", "vendor", "eggs", ".eggs"}
    skip_ext = {".pyc", ".pyo", ".class", ".jar", ".war", ".ear", ".so", ".dll",
                ".dylib", ".exe", ".bin", ".png", ".jpg", ".jpeg", ".gif", ".ico",
                ".woff", ".woff2", ".ttf", ".eot", ".map", ".min.js", ".min.css",
                ".lock", ".sum"}
    files = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for f in filenames:
            name, ext = os.path.splitext(f)
            _, ext2 = os.path.splitext(name)
            ext = ext.lower()
            full_ext = (ext2 + ext).lower()
            if ext in skip_ext or full_ext in skip_ext:
                continue
            if f.endswith((".min.js", ".min.css")):
                continue
            full_path = os.path.join(dirpath, f)
            rel_path = os.path.relpath(full_path, repo_path)
            files.append(rel_path)
            if len(files) >= max_files:
                return files
    return sorted(files)


def detect_language(repo_path):
    """Detect the primary language/framework of a codebase."""
    root_files = set(f.lower() for f in os.listdir(repo_path) if os.path.isfile(os.path.join(repo_path, f)))
    all_files = list_repo_files(repo_path, max_files=50)
    all_lower = set(f.lower() for f in all_files)

    # Check for framework indicators
    is_fastapi = any("fastapi" in f.lower() or "starlette" in f.lower() for f in all_lower)
    is_flask = any("flask" in f.lower() for f in all_lower) and "flask" not in str(all_lower)
    is_django = any("django" in f.lower() for f in all_lower) or "manage.py" in root_files
    is_spring = any(f.endswith("Application.java") or "spring" in f.lower() or "pom.xml" in root_files or "build.gradle" in root_files for f in all_lower)
    is_express = "package.json" in root_files and any("express" in f.lower() for f in all_lower)
    is_next = "next.config.js" in root_files or "next.config.mjs" in root_files
    is_go = any(f.endswith(".go") for f in all_lower) or "go.mod" in root_files
    is_rust = "cargo.toml" in root_files
    is_dotnet = any(f.endswith(".csproj") or f.endswith(".sln") for f in all_lower)

    if is_fastapi:
        return "python", "fastapi"
    if is_flask:
        return "python", "flask"
    if is_django:
        return "python", "django"
    if is_spring:
        return "java", "spring"
    if is_express:
        return "javascript", "express"
    if is_next:
        return "javascript", "nextjs"
    if is_go:
        return "go", "go"
    if is_rust:
        return "rust", "rust"
    if is_dotnet:
        return "csharp", "dotnet"
    if any(f.endswith(".py") for f in all_lower):
        return "python", "generic"
    if any(f.endswith(".java") for f in all_lower):
        return "java", "generic"
    if any(f.endswith(".js") or f.endswith(".ts") for f in all_lower):
        return "javascript", "generic"
    if any(f.endswith(".go") for f in all_lower):
        return "go", "generic"
    return "unknown", "unknown"


def parse_dependencies(repo_path, language):
    """Extract dependencies from a repo."""
    deps = []
    if language == "python":
        deps = _parse_python_deps(repo_path)
    elif language == "java":
        deps = _parse_java_deps(repo_path)
    elif language == "javascript":
        deps = _parse_js_deps(repo_path)
    elif language == "go":
        deps = _parse_go_deps(repo_path)
    return deps


def _parse_python_deps(repo_path):
    deps = []
    req_file = os.path.join(repo_path, "requirements.txt")
    if os.path.isfile(req_file):
        with open(req_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    # Parse name==version or name>=version or name~=version
                    for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
                        if sep in line:
                            name, version = line.split(sep, 1)
                            deps.append({"name": name.strip(), "version": version.strip().split(";")[0].strip()})
                            break
                    else:
                        deps.append({"name": line.split(";")[0].strip(), "version": ""})
    # Also check pyproject.toml / poetry / pipfile
    pyproject = os.path.join(repo_path, "pyproject.toml")
    if os.path.isfile(pyproject):
        try:
            with open(pyproject, "r") as f:
                content = f.read()
            import re
            for m in re.finditer(r'([\w-]+)\s*=\s*"[^"]*(\d+\.\d+[^"]*)"', content):
                deps.append({"name": m.group(1), "version": m.group(2)})
        except Exception:
            pass
    return deps


def _parse_java_deps(repo_path):
    deps = []
    # pom.xml
    pom = os.path.join(repo_path, "pom.xml")
    if os.path.isfile(pom):
        try:
            with open(pom, "r") as f:
                content = f.read()
            import re
            # Match <groupId>...</groupId><artifactId>...</artifactId><version>...</version> blocks
            for block in re.finditer(r'<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>', content):
                gid, aid, ver = block.groups()
                if not ver.startswith("${"):
                    deps.append({"name": f"{gid}:{aid}", "version": ver})
        except Exception:
            pass
    # build.gradle
    gradle = os.path.join(repo_path, "build.gradle")
    if os.path.isfile(gradle):
        try:
            with open(gradle, "r") as f:
                content = f.read()
            import re
            for m in re.finditer(r"(?:implementation|compile|api|runtimeOnly)\s+['\"]([^'\"]+):([^'\"]+):([^'\"]+)['\"]", content):
                deps.append({"name": f"{m.group(1)}:{m.group(2)}", "version": m.group(3)})
        except Exception:
            pass
    return deps


def _parse_js_deps(repo_path):
    deps = []
    pkg = os.path.join(repo_path, "package.json")
    if os.path.isfile(pkg):
        try:
            import json
            with open(pkg, "r") as f:
                data = json.load(f)
            for section in ("dependencies", "devDependencies"):
                for name, version in data.get(section, {}).items():
                    clean_ver = version.lstrip("^~>=<")
                    deps.append({"name": name, "version": clean_ver})
        except Exception:
            pass
    return deps


def _parse_go_deps(repo_path):
    deps = []
    gomod = os.path.join(repo_path, "go.mod")
    if os.path.isfile(gomod):
        try:
            with open(gomod, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("require ") or line.startswith("\t"):
                        parts = line.split()
                        if len(parts) >= 2 and not parts[0] in ("require", "module", "go"):
                            name = parts[0]
                            version = parts[1].lstrip("v") if len(parts) > 1 else ""
                            if "/" in name and "." in name:
                                deps.append({"name": name, "version": version})
        except Exception:
            pass
    return deps


# ── Exceptions ──

class StorageLimitExceeded(Exception):
    pass


class CloneFailed(Exception):
    pass
