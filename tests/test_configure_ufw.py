"""Exercise setup safeguards without changing the host firewall."""

import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import configure_ufw as setup


class SetupChecks(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(
            patch.object(setup.os, "geteuid", return_value=0, create=True)
        )
        self.stack.enter_context(
            patch.object(setup.sys.stdin, "isatty", return_value=True)
        )
        self.which = self.stack.enter_context(
            patch.object(setup.shutil, "which", return_value="/usr/sbin/tool")
        )
        self.run = self.stack.enter_context(patch.object(setup, "run"))
        self.backup = self.stack.enter_context(
            patch.object(
                setup.tempfile, "mkstemp", return_value=(123, "/root/backup.tar.gz")
            )
        )
        self.stack.enter_context(patch.object(setup.os, "close"))

    def invoke(self, answers, *args):
        with (
            patch.object(sys, "argv", ["configure_ufw.py", *args]),
            patch("builtins.input", side_effect=answers),
        ):
            setup.main()
        return [call.args for call in self.run.call_args_list]

    def test_restricted_dual_stack_and_order(self):
        rules = setup.build_rules("01314", "192.0.2.10,2001:db8::10", True, True, True)
        self.assertEqual(len(rules), 7)
        for rule in rules[:2]:
            self.assertEqual(
                rule[:6], ["prepend", "allow", "in", "proto", "tcp", "from"]
            )
            self.assertEqual(rule[rule.index("port") + 1], "1314")
        self.assertIn("192.0.2.10/32", rules[0])
        self.assertIn("2001:db8::10/128", rules[1])
        self.assertEqual(
            rules[-2:],
            [["default", "allow", "outgoing"], ["default", "deny", "incoming"]],
        )
        minimal = setup.build_rules("22", "192.0.2.10")
        self.assertEqual(len(minimal), 2)
        self.assertNotIn(["default", "allow", "outgoing"], minimal)

    def test_invalid_inputs_cannot_create_rules(self):
        for port in ("", "0", "65536", "22;id", "-1", "ssh"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                setup.build_rules(port, "192.0.2.10")
        for source in (
            "",
            "any",
            "0.0.0.0/0",
            "::/0",
            "2001:db8::1/0",
            "192.0.2.10;id",
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                setup.build_rules("22", source)
        with self.assertRaises(ValueError):
            setup.build_rules("443", "192.0.2.10", web=True)

    def test_preview_never_enables_or_backs_up(self):
        calls = self.invoke(["1314", "192.0.2.10", "y", "y", "y"], "--dry-run")
        mutations = [
            call
            for call in calls
            if call[:2] not in {("ss", "-lnt"), ("ufw", "status"), ("ufw", "show")}
        ]
        self.assertTrue(mutations)
        self.assertTrue(all(call[:2] == ("ufw", "--dry-run") for call in mutations))
        self.assertFalse(any("enable" in call for call in calls))
        self.backup.assert_not_called()

    def test_cancel_makes_no_changes(self):
        calls = self.invoke(["1314", "192.0.2.10", "", "", "", ""])
        self.assertEqual(
            calls,
            [("ss", "-lnt"), ("ufw", "status", "verbose"), ("ufw", "show", "added")],
        )
        self.backup.assert_not_called()

    def test_apply_validates_then_backs_up_then_ssh_then_enable(self):
        calls = self.invoke(["1314", "192.0.2.10", "y", "y", "y", "APPLY"])
        backup = next(i for i, call in enumerate(calls) if call[0] == "tar")
        ssh = next(i for i, call in enumerate(calls) if call[:2] == ("ufw", "prepend"))
        default = calls.index(("ufw", "default", "deny", "incoming"))
        enable = calls.index(("ufw", "enable"))
        self.assertLess(backup, ssh)
        self.assertLess(ssh, default)
        self.assertLess(default, enable)
        self.assertTrue(
            all(i < backup for i, call in enumerate(calls) if "--dry-run" in call)
        )
        self.assertFalse(
            any(
                "--force" in call or "reset" in call or "delete" in call
                for call in calls
            )
        )

    def test_failed_validation_stops_before_mutations(self):
        def fail(*command):
            if "--dry-run" in command:
                raise subprocess.CalledProcessError(1, command)

        self.run.side_effect = fail
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(["1314", "192.0.2.10", "", "", "", "APPLY"])
        self.backup.assert_not_called()
        self.assertFalse(
            any(call.args == ("ufw", "enable") for call in self.run.call_args_list)
        )

    def test_backup_failure_stops_before_mutations(self):
        def fail(*command):
            if command[0] == "tar":
                raise subprocess.CalledProcessError(1, command)

        self.run.side_effect = fail
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(["1314", "192.0.2.10", "", "", "", "APPLY"])
        self.assertFalse(
            any(call.args[:2] == ("ufw", "prepend") for call in self.run.call_args_list)
        )

    def test_missing_ufw_preview_does_not_install(self):
        self.which.side_effect = lambda name: None if name == "ufw" else "/usr/bin/tool"
        with self.assertRaisesRegex(ValueError, "install UFW first"):
            self.invoke(["1314", "192.0.2.10", "", "", ""], "--dry-run")
        self.assertFalse(
            any(call.args[0] == "apt-get" for call in self.run.call_args_list)
        )
        self.backup.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Bash bootstrap runs on Linux")
    def test_download_failure_never_runs_setup_and_removes_tempfile(self):
        readme = Path(__file__).resolve().parents[1].joinpath("README.md").read_text()
        launcher = next(
            block
            for block in re.findall(r"\x60{3}bash\n(.*?)\x60{3}", readme, re.DOTALL)
            if "setup=$(mktemp)" in block
        )
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for name, script in {
                "curl": "exit 22",
                "sudo": 'touch "$TMPDIR/executed"',
            }.items():
                path = directory / name
                path.write_text("#!/bin/sh\n" + script + "\n")
                path.chmod(0o700)
            result = subprocess.run(
                ["bash", "-c", launcher],
                check=False,
                env={
                    **os.environ,
                    "PATH": folder + os.pathsep + os.environ["PATH"],
                    "TMPDIR": folder,
                },
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 22)
            self.assertEqual(
                {path.name for path in directory.iterdir()}, {"curl", "sudo"}
            )


if __name__ == "__main__":
    unittest.main()
