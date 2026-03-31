# Axios Scanner

`axios_scanner.py` scans a directory tree for the March 31, 2026 Axios npm compromise involving `axios@1.14.1`, `axios@0.30.4`, and the injected `plain-crypto-js` dependency.

## What it does

- Scans `package.json` for explicit bad Axios pins.
- Scans `package-lock.json`, `npm-shrinkwrap.json`, and `node_modules/.package-lock.json`.
- Scans installed `node_modules/axios` and `node_modules/plain-crypto-js`, including nested installs.
- Flags `yarn.lock` and `pnpm-lock.yaml` entries, but leaves those lockfiles unchanged.
- Scans JS files inside compromised `node_modules/axios` and `node_modules/plain-crypto-js` for malicious payload indicators (`execSync`, `writeFileSync`, C2 domains).
- Checks lockfile integrity hashes against known-bad values (extensible via `KNOWN_BAD_INTEGRITY_PREFIXES`).
- Detects `package.md` files in axios directories -- a self-destruct remnant left by the malware after it cleans up its own traces.
- Optionally checks the local filesystem for RAT artifacts dropped by the malware.
- Scans the npm cache (`~/.npm/_cacache`) for cached copies of compromised tarballs.

## Usage

Scan in read-only mode:

```bash
python3 axios_scanner.py /path/to/repo
```

JSON output (for CI pipelines):

```bash
python3 axios_scanner.py --json /path/to/repo
```

Check for RAT artifacts on the local system:

```bash
python3 axios_scanner.py --check-system /path/to/repo
```

This mode also works when the target directory has no JavaScript project files. Any accessible directory path is fine.

Apply npm-focused remediation:

```bash
python3 axios_scanner.py --fix /path/to/repo
```

**Warning:** `--fix` is destructive -- it rewrites lockfiles in place and deletes directories from `node_modules`. Always run without `--fix` first to review findings, and make sure your work is committed before running remediation.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | No compromise indicators found |
| 1    | Findings detected, including host-level IOCs that remain after `--fix --check-system` |

## Remediation behavior

`--fix` will:

- rewrite explicit `axios` manifest specs from `1.14.1` to `1.14.0` and `0.30.4` to `0.30.3`
- repair npm lockfile entries for compromised Axios versions (including nested entries)
- remove `plain-crypto-js` from npm lockfiles
- delete installed `node_modules/axios` and `node_modules/plain-crypto-js` when they match compromise indicators (including nested `node_modules`)

## System IOC paths

`--check-system` looks for RAT artifacts the malware drops after execution:

| OS      | Path                                    |
|---------|-----------------------------------------|
| macOS   | `/Library/Caches/com.apple.act.mond`    |
| Windows | `%PROGRAMDATA%\wt.exe`                  |
| Linux   | `/tmp/ld.py`                            |

The malware self-destructs its npm traces after execution, so a clean `node_modules` does not guarantee the system wasn't compromised. Use `--check-system` to verify. This also scans the npm cache (`~/.npm/_cacache`) for references to the compromised tarballs.

The scanner also detects `package.md` files inside axios directories in `node_modules`. The malware creates this file during its self-destruct sequence (it overwrites the real `package.json` from `package.md`). If you see this finding, the malware executed on that machine -- treat it as compromised even if everything else looks clean.

If you combine `--fix --check-system`, the command still exits with findings until those host-level artifacts are removed.

## Limits

- `yarn.lock` and `pnpm-lock.yaml` are detection-only; regenerate them with the native package manager after review. The text lockfile parser is heuristic-based (indent and header detection), so unusual formatting may be missed. When in doubt, regenerate the lockfile.
- Lockfile repair fetches safe Axios metadata from the npm registry.
- Version spec rewriting handles `^`, `~`, `=`, and exact pins. Range specs like `>=1.14.1` are not rewritten.
- `KNOWN_BAD_INTEGRITY_PREFIXES` ships empty. Add confirmed SRI hash prefixes from security advisories to enable integrity-based detection. This is a defense-in-depth layer for catching tampered packages where the version field has been altered.
- If the malware already executed and fully cleaned up (removed `package.md`, cleared cache), detection relies on the RAT artifact paths under `--check-system`. There is no guaranteed detection after a complete cleanup.

## Source Material

- https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
- https://github.com/axios/axios/issues/10604
