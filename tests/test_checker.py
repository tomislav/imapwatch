import logging
import threading
import unittest
from unittest.mock import patch

import imapclient.exceptions

from lib.imapwatch.checker import Checker, CheckerThread


class ImmediateEvent(threading.Event):
    """Do not make reconnect tests wait for the production backoff."""

    def wait(self, timeout=None):
        return self.is_set()


class Client:
    def __init__(self, event, *, idle_error=None, select_error=None):
        self.event = event
        self.idle_error = idle_error
        self.select_error = select_error
        self.logged_out = False

    def login(self, username, password):
        return None

    def select_folder(self, mailbox):
        if self.select_error:
            raise self.select_error

    def idle(self):
        return None

    def idle_check(self, timeout):
        if self.idle_error:
            raise self.idle_error
        self.event.set()
        return []

    def idle_done(self):
        return None

    def logout(self):
        self.logged_out = True


class CheckerReconnectTests(unittest.TestCase):
    def test_failed_reconnect_is_retried_without_killing_thread(self):
        event = ImmediateEvent()
        clients = [
            Client(
                event,
                idle_error=imapclient.exceptions.IMAPClientError(
                    "NOOP failed: Internal server error"
                ),
            ),
            Client(
                event,
                select_error=imapclient.exceptions.IMAPClientError(
                    "select failed: Internal server error"
                ),
            ),
            Client(event),
        ]
        logger = logging.getLogger(self.id())
        checker = Checker(
            logger,
            event,
            "imap.example.test",
            "user",
            "password",
            "INBOX",
            ["new"],
            {"action": "things", "email": "things@example.test"},
            sender=None,
            use_ssl=False,
        )
        checker_thread = CheckerThread(logger, checker)

        with patch(
            "lib.imapwatch.checker.imapclient.IMAPClient", side_effect=clients
        ) as imap_client:
            checker_thread.run()

        self.assertEqual(imap_client.call_count, 3)
        self.assertTrue(clients[-1].logged_out)
        self.assertFalse(checker.connected)


if __name__ == "__main__":
    unittest.main()
