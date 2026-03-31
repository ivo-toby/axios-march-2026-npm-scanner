import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from axios_scanner import Finding, fix_project, main, scan_paths, scan_project


class StubRegistryClient:
    def fetch_package_version(self, name: str, version: str) -> dict:
        self.last_request = (name, version)
        return {
            "name": "axios",
            "version": "1.14.0",
            "dist": {
                "tarball": "https://registry.npmjs.org/axios/-/axios-1.14.0.tgz",
                "integrity": "sha512-safe",
            },
            "dependencies": {
                "follow-redirects": "^1.15.11",
                "form-data": "^4.0.5",
                "proxy-from-env": "^2.1.0",
            },
        }


class AxiosScannerTests(unittest.TestCase):
    def test_fix_project_rewrites_malicious_package_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lockfile = root / "package-lock.json"
            lockfile.write_text(
                json.dumps(
                    {
                        "name": "demo",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"axios": "^1.14.1"}},
                            "node_modules/axios": {
                                "version": "1.14.1",
                                "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz",
                                "integrity": "sha512-malicious",
                                "dependencies": {
                                    "follow-redirects": "^1.15.11",
                                    "form-data": "^4.0.5",
                                    "plain-crypto-js": "^4.2.1",
                                    "proxy-from-env": "^2.1.0",
                                },
                            },
                            "node_modules/plain-crypto-js": {
                                "version": "4.2.1",
                                "resolved": "https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz",
                                "integrity": "sha512-rat",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            findings = scan_project(root)

            self.assertEqual(2, len(findings))
            self.assertEqual({"axios", "plain-crypto-js"}, {finding.package for finding in findings})

            fixed = fix_project(root, StubRegistryClient())

            self.assertEqual(1, fixed.files_modified)

            rewritten = json.loads(lockfile.read_text(encoding="utf-8"))
            self.assertEqual("^1.14.0", rewritten["packages"][""]["dependencies"]["axios"])
            axios_entry = rewritten["packages"]["node_modules/axios"]
            self.assertEqual("1.14.0", axios_entry["version"])
            self.assertNotIn("plain-crypto-js", axios_entry["dependencies"])
            self.assertNotIn("node_modules/plain-crypto-js", rewritten["packages"])

    def test_fix_project_rewrites_bad_package_json_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package_json = root / "package.json"
            package_json.write_text(
                json.dumps(
                    {
                        "name": "demo",
                        "dependencies": {"axios": "^1.14.1"},
                        "devDependencies": {"axios": "0.30.4"},
                    }
                ),
                encoding="utf-8",
            )

            findings = scan_project(root)

            self.assertEqual(2, len(findings))

            fixed = fix_project(root, StubRegistryClient())

            self.assertEqual(1, fixed.files_modified)

            rewritten = json.loads(package_json.read_text(encoding="utf-8"))
            self.assertEqual("^1.14.0", rewritten["dependencies"]["axios"])
            self.assertEqual("0.30.3", rewritten["devDependencies"]["axios"])

    def test_fix_project_removes_installed_malicious_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            axios_package = root / "node_modules" / "axios" / "package.json"
            axios_package.parent.mkdir(parents=True)
            axios_package.write_text(
                json.dumps({"name": "axios", "version": "1.14.1"}),
                encoding="utf-8",
            )

            rat_package = root / "node_modules" / "plain-crypto-js" / "package.json"
            rat_package.parent.mkdir(parents=True)
            rat_package.write_text(
                json.dumps({"name": "plain-crypto-js", "version": "4.2.1"}),
                encoding="utf-8",
            )

            findings = scan_project(root)

            self.assertEqual(2, len(findings))

            fixed = fix_project(root, StubRegistryClient())

            self.assertEqual(2, fixed.paths_removed)
            self.assertFalse(axios_package.parent.exists())
            self.assertFalse(rat_package.parent.exists())

    def test_scan_project_flags_yarn_lock_without_editing_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yarn_lock = root / "yarn.lock"
            original = (
                'axios@npm:^1.14.0:\n'
                '  version "1.14.1"\n'
                '  dependencies:\n'
                '    plain-crypto-js "^4.2.1"\n'
            )
            yarn_lock.write_text(original, encoding="utf-8")

            findings = scan_project(root)

            self.assertEqual(2, len(findings))

            fixed = fix_project(root, StubRegistryClient())

            self.assertEqual(0, fixed.files_modified)
            self.assertEqual(original, yarn_lock.read_text(encoding="utf-8"))

    def test_scan_paths_discovers_nested_projects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_root = root / "packages" / "api"
            project_root.mkdir(parents=True)
            (project_root / "package.json").write_text(
                json.dumps({"dependencies": {"axios": "1.14.1"}}),
                encoding="utf-8",
            )

            findings = scan_paths([root])

            self.assertEqual(1, len(findings))
            self.assertEqual(project_root / "package.json", findings[0].path)

    def test_main_returns_nonzero_when_findings_are_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"axios": "1.14.1"}}),
                encoding="utf-8",
            )
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main([str(root)])

            self.assertEqual(1, exit_code)
            self.assertIn("axios", output.getvalue())

    def test_fix_project_updates_legacy_dependency_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lockfile = root / "package-lock.json"
            lockfile.write_text(
                json.dumps(
                    {
                        "name": "demo",
                        "lockfileVersion": 1,
                        "dependencies": {
                            "axios": {
                                "version": "0.30.4",
                                "resolved": "https://registry.npmjs.org/axios/-/axios-0.30.4.tgz",
                                "integrity": "sha512-malicious",
                                "requires": {
                                    "follow-redirects": "^1.15.4",
                                    "form-data": "^4.0.4",
                                    "plain-crypto-js": "^4.2.1",
                                    "proxy-from-env": "^1.1.0",
                                },
                            },
                            "plain-crypto-js": {
                                "version": "4.2.1",
                                "resolved": "https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            findings = scan_project(root)

            self.assertEqual(2, len(findings))

            fixed = fix_project(root, StubRegistryClient())

            self.assertEqual(1, fixed.files_modified)

            rewritten = json.loads(lockfile.read_text(encoding="utf-8"))
            axios_entry = rewritten["dependencies"]["axios"]
            self.assertEqual("1.14.0", axios_entry["version"])
            self.assertNotIn("plain-crypto-js", axios_entry["requires"])
            self.assertNotIn("plain-crypto-js", rewritten["dependencies"])

    def test_main_checks_system_iocs_without_project_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = StringIO()

            with mock.patch(
                "axios_scanner.scan_system_iocs",
                return_value=[Finding(path=Path("/tmp/ioc"), package="axios-rat", reason="ioc")],
            ):
                with redirect_stdout(output):
                    exit_code = main(["--check-system", str(root)])

            self.assertEqual(1, exit_code)
            self.assertIn("/tmp/ioc", output.getvalue())

    def test_main_json_output_without_project_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["--json", str(root)])

            self.assertEqual(0, exit_code)
            payload = json.loads(output.getvalue())
            self.assertEqual("clean", payload["status"])
            self.assertEqual([], payload["findings"])

    def test_scan_project_finds_compromised_axios_in_scoped_nested_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scoped_axios = root / "node_modules" / "@vendor" / "pkg" / "node_modules" / "axios"
            scoped_axios.mkdir(parents=True)
            (scoped_axios / "package.json").write_text(
                json.dumps({"name": "axios", "version": "1.14.1"}),
                encoding="utf-8",
            )

            findings = scan_project(root)

            self.assertEqual(1, len(findings))
            self.assertEqual("axios", findings[0].package)

    def test_main_fix_check_system_keeps_reporting_remaining_system_iocs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"axios": "^1.14.1"}}),
                encoding="utf-8",
            )
            output = StringIO()

            with mock.patch(
                "axios_scanner.scan_system_iocs",
                return_value=[Finding(path=Path("/tmp/ioc"), package="axios-rat", reason="ioc")],
            ):
                with redirect_stdout(output):
                    exit_code = main(["--fix", "--check-system", str(root)])

            self.assertEqual(1, exit_code)
            self.assertIn("Remaining findings", output.getvalue())
            self.assertNotIn("Remediation complete.", output.getvalue())

    def test_scan_project_reports_invalid_json_lockfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text(
                '{\n  "name": "demo",\n<<<<<<< HEAD\n  "lockfileVersion": 3\n=======\n  "lockfileVersion": 2\n>>>>>>> branch\n}\n',
                encoding="utf-8",
            )

            findings = scan_project(root)

            self.assertEqual(1, len(findings))
            self.assertEqual("scanner-error", findings[0].package)
            self.assertIn("invalid JSON", findings[0].reason)

    def test_main_fix_does_not_crash_on_invalid_json_lockfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text(
                '{\n  "name": "demo",\n<<<<<<< HEAD\n  "lockfileVersion": 3\n=======\n  "lockfileVersion": 2\n>>>>>>> branch\n}\n',
                encoding="utf-8",
            )
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["--fix", str(root)])

            self.assertEqual(1, exit_code)
            self.assertIn("scanner-error", output.getvalue())

    def test_scan_project_ignores_unrelated_text_lockfile_version_mentions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "yarn.lock").write_text(
                'left-pad@1.3.0:\n'
                '  version "1.14.1"\n',
                encoding="utf-8",
            )

            findings = scan_project(root)

            self.assertEqual([], findings)

    def test_scan_project_ignores_generic_payload_signatures_in_safe_axios(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            axios_dir = root / "node_modules" / "axios"
            axios_dir.mkdir(parents=True)
            (axios_dir / "package.json").write_text(
                json.dumps({"name": "axios", "version": "0.27.2"}),
                encoding="utf-8",
            )
            (axios_dir / "helper.js").write_text(
                'const { execSync } = require("child_process");\n'
                'fs.writeFileSync("x", "y");\n',
                encoding="utf-8",
            )

            findings = scan_project(root)

            self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
