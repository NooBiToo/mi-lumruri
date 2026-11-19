"""Прогон быстрого установщика без соединения с роутером."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("installer", Path(__file__).resolve().parents[1] / "install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.package = Path(tmp.name) / "mi-trusttunnel-ci-123456789abc.tar"
        script = b"printf 'installed\\n'\n"
        with tarfile.open(self.package, "w") as archive:
            entry = tarfile.TarInfo("mi-trusttunnel/install.sh")
            entry.size = len(script)
            archive.addfile(entry, io.BytesIO(script))
        self.digest = hashlib.sha256(self.package.read_bytes()).hexdigest()
        (self.package.parent / "SHA256SUMS").write_text(f"{self.digest}  {self.package.name}\n")

    def test_zip_layout_works_offline(self):
        commands = []

        def run(command, **kwargs):
            commands.append(command)
            if "stdin" in kwargs:
                self.assertEqual(kwargs["stdin"].read(), self.package.read_bytes())

        with patch.object(installer, "__file__", str(self.package.parent / "install.py")), \
             patch.object(sys, "argv", ["install.py"]), patch.object(subprocess, "run", run):
            installer.main()
        self.assertEqual([command[:2] + command[-2:-1] for command in commands],
                         [["ssh", "-T", "root@192.168.31.1"], ["ssh", "-t", "root@192.168.31.1"]])
        self.assertTrue(all("HostKeyAlgorithms=+ssh-rsa" in command for command in commands))

    def test_store_is_passed_to_router_installer(self):
        commands = []
        with patch.object(sys, "argv", ["install.py", "--package", str(self.package), "--store", "/mnt/usb-1a2b/mitt"]), \
             patch.object(subprocess, "run", lambda command, **kwargs: commands.append(command)):
            installer.main()
        self.assertTrue(commands[0][-1].endswith("sh install.sh install --store=/mnt/usb-1a2b/mitt\n"))

    def test_unsafe_store_stops_before_ssh(self):
        with patch.object(sys, "argv", ["install.py", "--package", str(self.package), "--store", "/mnt/usb; reboot"]), \
             patch.object(subprocess, "run") as run, self.assertRaises(ValueError):
            installer.main()
        run.assert_not_called()

    def test_damaged_package_stops_before_ssh(self):
        with self.package.open("ab") as stream:
            stream.write(b"x")
        with patch.object(sys, "argv", ["install.py", "--package", str(self.package)]), \
             patch.object(subprocess, "run") as run, self.assertRaises(ValueError):
            installer.main()
        run.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "requires sh, openssl and tar")
    def test_remote_checksum_precedes_installation(self):
        for digest, success in [(self.digest, True), ("0" * 64, False)]:
            proc = subprocess.run(["sh", "-c", installer.INSTALL.replace("EXPECTED_SHA", digest)],
                                  input=self.package.read_bytes(), capture_output=True)
            self.assertEqual(proc.returncode == 0, success)
            self.assertEqual(b"installed" in proc.stdout, success)


if __name__ == "__main__":
    unittest.main()
