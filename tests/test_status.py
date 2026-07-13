import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from daemon.pidfile import TimeoutPIDLockFile


class StatusTests(unittest.TestCase):
    def test_unhealthy_checker_identifies_account_and_mailbox(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = os.path.join(directory, "imapwatch.pid")
            health_path = os.path.join(directory, "imapwatch.health")
            pidfile = TimeoutPIDLockFile(pid_path, timeout=1)
            pidfile.acquire()
            try:
                with open(health_path, "w", encoding="UTF-8") as health_file:
                    json.dump(
                        {
                            "pid": os.getpid(),
                            "updated_at": 10**12,
                            "healthy": False,
                            "checkers": [
                                {
                                    "account": "provider",
                                    "mailbox": "INBOX",
                                    "healthy": False,
                                }
                            ],
                        },
                        health_file,
                    )

                result = subprocess.run(
                    [
                        sys.executable,
                        str(Path(__file__).resolve().parents[1] / "imapwatch"),
                        "--pidfile",
                        pid_path,
                        "--healthfile",
                        health_path,
                        "status",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            finally:
                pidfile.release()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provider/INBOX", result.stderr)


if __name__ == "__main__":
    unittest.main()
