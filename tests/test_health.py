import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from lib.imapwatch import IMAPWatch


class FakeThread:
    def __init__(self, checker, alive=True):
        self.checker = checker
        self.name = "INBOX"
        self.alive = alive

    def is_alive(self):
        return self.alive


class HealthStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.healthfile = os.path.join(
            self.temporary_directory.name, "imapwatch.health"
        )
        self.checker = SimpleNamespace(
            account="provider",
            mailbox="INBOX",
            action_name="things",
            connected=True,
            last_activity=95,
        )
        self.thread = FakeThread(self.checker)
        self.watch = IMAPWatch.__new__(IMAPWatch)
        self.watch.healthfile = self.healthfile
        self.watch.threads = [self.thread]

    def read_health(self):
        with open(self.healthfile, "r", encoding="UTF-8") as health_file:
            return json.load(health_file)

    @patch("lib.imapwatch.time.time", return_value=100)
    def test_connected_live_checker_is_healthy(self, _time):
        self.watch.write_health()

        health = self.read_health()
        self.assertTrue(health["healthy"])
        self.assertTrue(health["checkers"][0]["healthy"])
        self.assertEqual(
            {
                key: health["checkers"][0][key]
                for key in ("account", "mailbox", "action", "thread_name")
            },
            {
                "account": "provider",
                "mailbox": "INBOX",
                "action": "things",
                "thread_name": "INBOX",
            },
        )

    @patch("lib.imapwatch.time.time", return_value=200)
    def test_stale_checker_heartbeat_is_unhealthy(self, _time):
        self.watch.write_health()

        health = self.read_health()
        self.assertFalse(health["healthy"])
        self.assertFalse(health["checkers"][0]["healthy"])

    @patch("lib.imapwatch.time.time", return_value=100)
    def test_dead_checker_thread_is_unhealthy(self, _time):
        self.thread.alive = False
        self.watch.write_health()

        self.assertFalse(self.read_health()["healthy"])

    @patch("lib.imapwatch.time.time", return_value=100)
    def test_same_mailbox_on_two_accounts_has_distinct_health_identity(self, _time):
        second_checker = SimpleNamespace(
            account="personal",
            mailbox="INBOX",
            action_name="omnifocus",
            connected=True,
            last_activity=95,
        )
        self.watch.threads.append(FakeThread(second_checker))

        self.watch.write_health()

        identities = [
            (checker["account"], checker["mailbox"], checker["action"])
            for checker in self.read_health()["checkers"]
        ]
        self.assertEqual(
            identities,
            [("provider", "INBOX", "things"), ("personal", "INBOX", "omnifocus")],
        )

    @patch("lib.imapwatch.time.time", return_value=100)
    def test_health_state_is_removed_only_by_its_owner(self, _time):
        self.watch.write_health()
        self.watch.remove_health()

        self.assertFalse(os.path.exists(self.healthfile))


if __name__ == "__main__":
    unittest.main()
