import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from axios_scanner import fix_project, main, scan_paths, scan_project


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


if __name__ == "__main__":
    unittest.main()
