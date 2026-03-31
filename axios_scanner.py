from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


COMPROMISED_AXIOS_VERSIONS = {
    "1.14.1": "1.14.0",
    "0.30.4": "0.30.3",
}
SUSPICIOUS_PACKAGE = "plain-crypto-js"
SUSPICIOUS_PACKAGE_VERSIONS = {"4.2.0", "4.2.1"}
PAYLOAD_SIGNATURES = [
    "execSync",
    "writeFileSync",
    "ProgramData",
    "com.apple.act.mond",
    "sfrclak.com",
]
# Known-bad integrity hash prefixes from compromised tarballs.
# Partial SRI hashes (first 52 chars) to match against lockfile integrity fields.
# Extend this set as security researchers confirm additional hashes.
KNOWN_BAD_INTEGRITY_PREFIXES: set[str] = set()
# Suspicious package names to look for in the npm cache.
NPM_CACHE_SUSPECT_PACKAGES = {"axios/-/axios-1.14.1.tgz", "axios/-/axios-0.30.4.tgz", "plain-crypto-js"}
SENTINEL_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}
SYSTEM_IOC_PATHS = {
    "Darwin": [Path("/Library/Caches/com.apple.act.mond")],
    "Windows": [Path(os.path.expandvars("%PROGRAMDATA%/wt.exe"))] if platform.system() == "Windows" else [],
    "Linux": [Path("/tmp/ld.py")],
}


@dataclass(frozen=True)
class Finding:
    path: Path
    package: str
    reason: str


@dataclass(frozen=True)
class FixReport:
    files_modified: int
    paths_removed: int


class RegistryClient:
    def fetch_package_version(self, name: str, version: str) -> dict[str, Any]:
        with urllib.request.urlopen(f"https://registry.npmjs.org/{name}/{version}", timeout=10) as response:
            package_info = json.load(response)
        if not package_info.get("version"):
            raise RuntimeError(f"npm registry did not return {name}@{version}")
        return package_info


def scan_project(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    package_json = root / "package.json"
    if package_json.exists():
        findings.extend(_scan_package_json(package_json))
    for lockfile_name in ("package-lock.json", "npm-shrinkwrap.json", ".package-lock.json"):
        lockfile = root / lockfile_name
        if not lockfile.exists():
            continue
        findings.extend(_scan_lockfile(lockfile))
    node_modules_lockfile = root / "node_modules" / ".package-lock.json"
    if node_modules_lockfile.exists():
        findings.extend(_scan_lockfile(node_modules_lockfile))
    for text_lockfile_name in ("yarn.lock", "pnpm-lock.yaml"):
        text_lockfile = root / text_lockfile_name
        if text_lockfile.exists():
            findings.extend(_scan_text_lockfile(text_lockfile))
    findings.extend(_scan_installed_packages(root))
    findings.extend(_scan_payload_files(root))
    findings.extend(_scan_post_execution_artifacts(root))
    return findings


def scan_paths(paths: list[str | Path]) -> list[Finding]:
    findings: list[Finding] = []
    for root in discover_project_roots(paths):
        findings.extend(scan_project(root))
    findings.sort(key=lambda finding: (str(finding.path), finding.package, finding.reason))
    return findings


def fix_project(root: Path, registry_client: Any) -> FixReport:
    files_modified = 0
    paths_removed = 0
    package_json = root / "package.json"
    if package_json.exists() and _fix_package_json(package_json):
        files_modified += 1
    for lockfile_name in ("package-lock.json", "npm-shrinkwrap.json"):
        lockfile = root / lockfile_name
        if lockfile.exists() and _fix_lockfile(lockfile, registry_client):
            files_modified += 1
    node_modules_lockfile = root / "node_modules" / ".package-lock.json"
    if node_modules_lockfile.exists() and _fix_lockfile(node_modules_lockfile, registry_client):
        files_modified += 1
    for package_dir in _find_installed_packages(root / "node_modules", "axios"):
        paths_removed += _remove_installed_package_if_needed(package_dir, compromised_versions=set(COMPROMISED_AXIOS_VERSIONS))
    for package_dir in _find_installed_packages(root / "node_modules", SUSPICIOUS_PACKAGE):
        paths_removed += _remove_installed_package_if_needed(package_dir, compromised_versions=None)
    return FixReport(files_modified=files_modified, paths_removed=paths_removed)


def discover_project_roots(paths: list[str | Path]) -> list[Path]:
    discovered: set[Path] = set()

    for raw_path in paths:
        candidate = Path(raw_path).resolve()
        if candidate.is_file():
            discovered.add(candidate.parent)
            continue
        if not candidate.exists():
            continue

        if any((candidate / sentinel).exists() for sentinel in SENTINEL_FILES):
            discovered.add(candidate)

        for current_root, dirnames, filenames in os.walk(candidate):
            dirnames[:] = [name for name in dirnames if name not in {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules", "dist", "build", ".next", ".output", "coverage"}]
            if SENTINEL_FILES.intersection(filenames):
                discovered.add(Path(current_root))

    return sorted(discovered)


def _scan_lockfile(path: Path) -> list[Finding]:
    data, error = _load_json_object(path)
    if error:
        return [error]
    findings: list[Finding] = []

    for package_path, package_data in data.get("packages", {}).items():
        integrity = package_data.get("integrity", "")
        is_axios = package_path.endswith("/axios") or package_path == "node_modules/axios"
        is_suspicious = package_path.endswith(f"/{SUSPICIOUS_PACKAGE}") or package_path == f"node_modules/{SUSPICIOUS_PACKAGE}"
        if is_axios:
            version = package_data.get("version")
            dependencies = package_data.get("dependencies", {})
            if version in COMPROMISED_AXIOS_VERSIONS or SUSPICIOUS_PACKAGE in dependencies:
                findings.append(Finding(path=path, package="axios", reason="compromised package-lock entry"))
            elif _integrity_is_known_bad(integrity):
                findings.append(Finding(path=path, package="axios", reason="known-bad integrity hash"))
        elif is_suspicious:
            findings.append(Finding(path=path, package=SUSPICIOUS_PACKAGE, reason="suspicious package present"))
        elif _integrity_is_known_bad(integrity):
            findings.append(Finding(path=path, package=package_path, reason="known-bad integrity hash"))

    findings.extend(_scan_legacy_dependencies(path, data.get("dependencies", {})))
    return findings


def _scan_package_json(path: Path) -> list[Finding]:
    data, error = _load_json_object(path)
    if error:
        return [error]
    findings: list[Finding] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = data.get(section, {})
        if not isinstance(values, dict):
            continue
        spec = values.get("axios")
        if isinstance(spec, str) and _rewrite_axios_spec(spec) != spec:
            findings.append(Finding(path=path, package="axios", reason=f"compromised version in {section}"))
    return findings


def _scan_installed_packages(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    node_modules = root / "node_modules"
    for package_dir in _find_installed_packages(node_modules, "axios"):
        package_json = package_dir / "package.json"
        package_data, error = _load_json_object(package_json)
        if error:
            findings.append(error)
            continue
        if package_data.get("version") in COMPROMISED_AXIOS_VERSIONS:
            findings.append(Finding(path=package_json, package="axios", reason="installed compromised axios"))
    for package_dir in _find_installed_packages(node_modules, SUSPICIOUS_PACKAGE):
        package_json = package_dir / "package.json"
        if package_json.exists():
            _, error = _load_json_object(package_json)
            if error:
                findings.append(error)
                continue
        findings.append(Finding(path=package_json, package=SUSPICIOUS_PACKAGE, reason="installed suspicious package"))
    return findings


def _scan_text_lockfile(path: Path) -> list[Finding]:
    contents = path.read_text(encoding="utf-8")
    findings: list[Finding] = []
    found_axios = False
    found_plain_crypto = False

    for header, body in _iter_text_lockfile_blocks(contents):
        header_mentions_axios = _header_mentions_package(header, "axios")
        header_mentions_plain_crypto = _header_mentions_package(header, SUSPICIOUS_PACKAGE)
        if header_mentions_axios and any(version in header or _block_mentions_version(body, version) for version in COMPROMISED_AXIOS_VERSIONS):
            found_axios = True
        if header_mentions_axios and _block_mentions_package_dependency(body, SUSPICIOUS_PACKAGE):
            found_plain_crypto = True
        if header_mentions_plain_crypto and any(version in header or _block_mentions_version(body, version) for version in SUSPICIOUS_PACKAGE_VERSIONS):
            found_plain_crypto = True

    if found_axios:
        findings.append(Finding(path=path, package="axios", reason="compromised version reference in text lockfile"))
    if found_plain_crypto:
        findings.append(Finding(path=path, package=SUSPICIOUS_PACKAGE, reason="suspicious package reference in text lockfile"))
    return findings


def _scan_legacy_dependencies(path: Path, dependencies: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for package_name, package_data in dependencies.items():
        if package_name == "axios":
            version = package_data.get("version")
            requires = package_data.get("requires", {})
            if version in COMPROMISED_AXIOS_VERSIONS or SUSPICIOUS_PACKAGE in requires:
                findings.append(Finding(path=path, package="axios", reason="compromised dependency tree entry"))
        if package_name == SUSPICIOUS_PACKAGE:
            findings.append(Finding(path=path, package=SUSPICIOUS_PACKAGE, reason="suspicious dependency tree entry"))
        findings.extend(_scan_legacy_dependencies(path, package_data.get("dependencies", {})))
    return findings


def scan_system_iocs() -> list[Finding]:
    findings: list[Finding] = []
    current_os = platform.system()
    for ioc_path in SYSTEM_IOC_PATHS.get(current_os, []):
        if ioc_path.exists():
            findings.append(Finding(path=ioc_path, package="axios-rat", reason=f"RAT artifact found ({current_os})"))
    findings.extend(_scan_npm_cache())
    return findings


def _scan_npm_cache() -> list[Finding]:
    findings: list[Finding] = []
    npm_cache = Path.home() / ".npm" / "_cacache"
    if not npm_cache.is_dir():
        return findings
    content_index = npm_cache / "content-v2"
    if not content_index.is_dir():
        return findings
    # Scan the index entries for references to suspect packages.
    index_dir = npm_cache / "index-v5"
    if not index_dir.is_dir():
        return findings
    for index_file in index_dir.rglob("*"):
        if not index_file.is_file():
            continue
        try:
            contents = index_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for suspect in NPM_CACHE_SUSPECT_PACKAGES:
            if suspect in contents:
                findings.append(Finding(
                    path=index_file,
                    package="axios-rat",
                    reason=f"npm cache contains reference to {suspect}",
                ))
                break
    return findings


def _scan_post_execution_artifacts(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    node_modules = root / "node_modules"
    if not node_modules.is_dir():
        return findings
    # The malware overwrites axios/package.json from a file called package.md
    # during self-destruct. The presence of package.md in an axios directory is
    # an indicator that the malware executed and cleaned up after itself.
    for axios_dir in _find_installed_packages(node_modules, "axios"):
        package_md = axios_dir / "package.md"
        if package_md.exists():
            findings.append(Finding(
                path=package_md,
                package="axios-rat",
                reason="post-execution artifact: package.md (malware self-destruct remnant)",
            ))
    # Also check for package.md in plain-crypto-js directories.
    for pkg_dir in _find_installed_packages(node_modules, SUSPICIOUS_PACKAGE):
        package_md = pkg_dir / "package.md"
        if package_md.exists():
            findings.append(Finding(
                path=package_md,
                package="axios-rat",
                reason="post-execution artifact: package.md (malware self-destruct remnant)",
            ))
    return findings


def _integrity_is_known_bad(integrity: str) -> bool:
    if not integrity or not KNOWN_BAD_INTEGRITY_PREFIXES:
        return False
    return any(integrity.startswith(prefix) for prefix in KNOWN_BAD_INTEGRITY_PREFIXES)


def _scan_payload_files(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    node_modules = root / "node_modules"
    for target_dir in [node_modules / "axios", node_modules / SUSPICIOUS_PACKAGE]:
        if not target_dir.is_dir():
            continue
        package_data, error = _load_json_object(target_dir / "package.json")
        if error or not _is_suspicious_installed_package(package_data):
            continue
        for js_file in target_dir.rglob("*.js"):
            try:
                contents = js_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            matched = [sig for sig in PAYLOAD_SIGNATURES if sig in contents]
            if len(matched) >= 2:
                findings.append(Finding(
                    path=js_file,
                    package="axios-rat",
                    reason=f"malicious payload indicators: {', '.join(matched)}",
                ))
    return findings


def _iter_text_lockfile_blocks(contents: str) -> list[tuple[str, str]]:
    lines = contents.splitlines()
    blocks: list[tuple[str, str]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.endswith(":"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent > 2:
            continue
        body_lines: list[str] = []
        for following in lines[index + 1:]:
            next_stripped = following.strip()
            next_indent = len(following) - len(following.lstrip(" "))
            if next_stripped.endswith(":") and next_indent <= indent:
                break
            body_lines.append(following)
        blocks.append((stripped, "\n".join(body_lines)))
    return blocks


def _header_mentions_package(header: str, package_name: str) -> bool:
    return re.search(rf'(^|[,"\']){re.escape(package_name)}@', header) is not None


def _block_mentions_version(block: str, version: str) -> bool:
    return re.search(rf'(?<![.\d]){re.escape(version)}(?![.\d])', block) is not None


def _block_mentions_package_dependency(block: str, package_name: str) -> bool:
    return re.search(rf'(^|\n)\s+{re.escape(package_name)}(?:\s|:)', block) is not None


def _is_suspicious_installed_package(package_data: dict[str, Any] | None) -> bool:
    if not package_data:
        return False
    name = package_data.get("name")
    version = package_data.get("version")
    return (
        name == "axios" and version in COMPROMISED_AXIOS_VERSIONS
    ) or (
        name == SUSPICIOUS_PACKAGE and version in SUSPICIOUS_PACKAGE_VERSIONS
    )


def _find_installed_packages(node_modules: Path, package_name: str) -> list[Path]:
    results: list[Path] = []
    candidate = node_modules / package_name
    if (candidate / "package.json").exists():
        results.append(candidate)
    if not node_modules.is_dir():
        return results
    for package_dir in _iter_package_dirs(node_modules):
        nested = package_dir / "node_modules"
        if nested.is_dir():
            results.extend(_find_installed_packages(nested, package_name))
    return results


def _iter_package_dirs(node_modules: Path) -> list[Path]:
    package_dirs: list[Path] = []
    for entry in node_modules.iterdir():
        if not entry.is_dir() or entry.name in {".", "..", ".cache", ".package-lock.json"}:
            continue
        if entry.name.startswith("@"):
            for scoped_entry in entry.iterdir():
                if scoped_entry.is_dir():
                    package_dirs.append(scoped_entry)
            continue
        package_dirs.append(entry)
    return package_dirs


def _fix_lockfile(path: Path, registry_client: Any) -> bool:
    data, error = _load_json_object(path)
    if error:
        return False
    packages = data.get("packages", {})
    modified = False

    root_entry = packages.get("", {})
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = root_entry.get(section, {})
        if not isinstance(values, dict):
            continue
        spec = values.get("axios")
        if not isinstance(spec, str):
            continue
        rewritten = _rewrite_axios_spec(spec)
        if rewritten != spec:
            values["axios"] = rewritten
            modified = True

    for package_path in list(packages):
        if package_path.endswith(f"/{SUSPICIOUS_PACKAGE}") or package_path == f"node_modules/{SUSPICIOUS_PACKAGE}":
            del packages[package_path]
            modified = True

    for package_path in list(packages):
        if not (package_path.endswith("/axios") or package_path == "node_modules/axios"):
            continue
        axios_entry = packages[package_path]
        current_version = axios_entry.get("version")
        target_version = COMPROMISED_AXIOS_VERSIONS.get(current_version)
        if target_version or SUSPICIOUS_PACKAGE in axios_entry.get("dependencies", {}):
            if target_version is None:
                target_version = "1.14.0"
            safe_metadata = registry_client.fetch_package_version("axios", target_version)
            axios_entry["version"] = safe_metadata["version"]
            axios_entry["resolved"] = safe_metadata["dist"]["tarball"]
            axios_entry["integrity"] = safe_metadata["dist"]["integrity"]
            axios_entry["dependencies"] = dict(safe_metadata.get("dependencies", {}))
            modified = True

    if _fix_legacy_dependencies(data.get("dependencies", {}), registry_client):
        modified = True

    if modified:
        path.write_text(f"{json.dumps(data, indent=2)}\n", encoding="utf-8")

    return modified


def _fix_package_json(path: Path) -> bool:
    data, error = _load_json_object(path)
    if error:
        return False
    modified = False
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = data.get(section, {})
        if not isinstance(values, dict):
            continue
        spec = values.get("axios")
        if not isinstance(spec, str):
            continue
        rewritten = _rewrite_axios_spec(spec)
        if rewritten != spec:
            values["axios"] = rewritten
            modified = True
    if modified:
        path.write_text(f"{json.dumps(data, indent=2)}\n", encoding="utf-8")
    return modified


def _rewrite_axios_spec(spec: str) -> str:
    for bad_version, safe_version in COMPROMISED_AXIOS_VERSIONS.items():
        for prefix in ("", "^", "~", "="):
            if spec == f"{prefix}{bad_version}":
                return f"{prefix}{safe_version}"
    return spec


def _remove_installed_package_if_needed(package_dir: Path, compromised_versions: set[str] | None) -> int:
    package_json = package_dir / "package.json"
    if not package_json.exists():
        return 0
    if compromised_versions is None:
        shutil.rmtree(package_dir)
        return 1
    package_data, error = _load_json_object(package_json)
    if error:
        return 0
    if package_data.get("version") not in compromised_versions:
        return 0
    shutil.rmtree(package_dir)
    return 1


def _load_json_object(path: Path) -> tuple[dict[str, Any] | None, Finding | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, Finding(
            path=path,
            package="scanner-error",
            reason=f"invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})",
        )
    except (OSError, UnicodeDecodeError) as exc:
        return None, Finding(path=path, package="scanner-error", reason=f"unable to read file: {exc}")
    if not isinstance(data, dict):
        return None, Finding(path=path, package="scanner-error", reason="expected top-level JSON object")
    return data, None


def _fix_legacy_dependencies(dependencies: dict[str, Any], registry_client: Any) -> bool:
    modified = False
    for package_name in list(dependencies):
        package_data = dependencies[package_name]
        if package_name == SUSPICIOUS_PACKAGE:
            del dependencies[package_name]
            modified = True
            continue
        if package_name == "axios":
            current_version = package_data.get("version")
            target_version = COMPROMISED_AXIOS_VERSIONS.get(current_version)
            if target_version or SUSPICIOUS_PACKAGE in package_data.get("requires", {}):
                if target_version is None:
                    target_version = "1.14.0"
                safe_metadata = registry_client.fetch_package_version("axios", target_version)
                package_data["version"] = safe_metadata["version"]
                package_data["resolved"] = safe_metadata["dist"]["tarball"]
                package_data["integrity"] = safe_metadata["dist"]["integrity"]
                package_data["requires"] = dict(safe_metadata.get("dependencies", {}))
                modified = True
        if _fix_legacy_dependencies(package_data.get("dependencies", {}), registry_client):
            modified = True
    return modified


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan for the Axios npm supply-chain compromise and optionally remediate npm projects."
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Project roots or directories to scan recursively.")
    parser.add_argument("--fix", action="store_true", help="Rewrite package.json and npm lockfiles, and remove malicious node_modules entries.")
    parser.add_argument("--check-system", action="store_true", help="Check for RAT artifacts on the local filesystem.")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON (useful for CI).")
    args = parser.parse_args(argv)

    project_roots = discover_project_roots(args.paths)
    findings: list[Finding] = []
    for root in project_roots:
        findings.extend(scan_project(root))
    if args.check_system:
        findings.extend(scan_system_iocs())
    findings.sort(key=lambda f: (str(f.path), f.package, f.reason))
    if not findings:
        if args.json:
            print(json.dumps({"status": "clean", "findings": []}))
        else:
            print("No Axios compromise indicators found.")
        return 0

    if args.json:
        print(json.dumps({
            "status": "compromised",
            "findings": [
                {"path": str(f.path), "package": f.package, "reason": f.reason}
                for f in findings
            ],
        }))

    else:
        for finding in findings:
            print(f"{finding.path}: {finding.package} ({finding.reason})")

    if not args.fix:
        return 1

    registry_client = RegistryClient()
    for root in project_roots:
        fix_project(root, registry_client)

    remaining = scan_paths([str(path) for path in project_roots])
    if args.check_system:
        remaining.extend(scan_system_iocs())
    remaining.sort(key=lambda f: (str(f.path), f.package, f.reason))
    if remaining:
        print("\nRemaining findings require manual package-manager remediation:")
        for finding in remaining:
            print(f"{finding.path}: {finding.package} ({finding.reason})")
        return 1

    print("\nRemediation complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
