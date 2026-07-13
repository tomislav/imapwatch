import logging
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import imapclient.exceptions

from lib.imapwatch import IMAPWatch
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


class CleanupClient:
    def __init__(
        self,
        *,
        supports_move=True,
        archive_exists=True,
        remove_error=None,
        move_error=None,
    ):
        self.supports_move = supports_move
        self.archive_exists = archive_exists
        self.remove_error = remove_error
        self.move_error = move_error
        self.calls = []
        self.logged_out = False

    def login(self, username, password):
        self.calls.append(call.login(username, password))

    def select_folder(self, mailbox):
        self.calls.append(call.select_folder(mailbox))

    def has_capability(self, capability):
        self.calls.append(call.has_capability(capability))
        return self.supports_move

    def folder_exists(self, folder):
        self.calls.append(call.folder_exists(folder))
        return self.archive_exists

    def remove_flags(self, uids, flags):
        self.calls.append(call.remove_flags(uids, flags))
        if self.remove_error:
            raise self.remove_error

    def move(self, uids, folder):
        self.calls.append(call.move(uids, folder))
        if self.move_error:
            raise self.move_error

    def logout(self):
        self.logged_out = True


def make_checker(**options):
    return Checker(
        Mock(),
        threading.Event(),
        "imap.example.test",
        "user",
        "password",
        "INBOX",
        ["flagged"],
        {"action": "things", "email": "things@example.test"},
        sender=Mock(),
        use_ssl=False,
        **options,
    )


class CheckerPostProcessingTests(unittest.TestCase):
    def test_options_default_to_disabled(self):
        checker = make_checker()

        self.assertFalse(checker.remove_flag_after_processing)
        self.assertIsNone(checker.archive_after_processing)

    def test_fetch_messages_retains_uid(self):
        checker = make_checker()
        checker.server = Mock()
        envelope = SimpleNamespace(
            message_id=b"message-id",
            subject=b"Subject",
            from_=[
                SimpleNamespace(
                    name=b"Sender", mailbox=b"sender", host=b"example.test"
                )
            ],
        )
        checker.server.fetch.return_value = {
            7: {b"ENVELOPE": envelope, b"UID": 1234}
        }

        items = checker.fetch_messages([7])

        checker.server.fetch.assert_called_once_with([7], ["ENVELOPE", "UID"])
        self.assertEqual(items[0]["uid"], 1234)

    def test_dispatch_passes_all_uids_to_success_callback(self):
        checker = make_checker(remove_flag_after_processing=True)
        checker.post_process = Mock()
        items = [
            {"from_": "First", "subject": "One", "message_id": "1", "uid": 11},
            {"from_": "Second", "subject": "Two", "message_id": "2", "uid": 12},
        ]

        with patch("lib.imapwatch.checker.SenderThread") as sender_thread:
            checker.dispatch(items)

        sender_thread.return_value.start.assert_called_once()
        on_success = sender_thread.call_args.kwargs["on_success"]
        on_success()
        checker.post_process.assert_called_once_with([11, 12])

    def test_remove_flag_only(self):
        checker = make_checker(remove_flag_after_processing=True)
        cleanup = CleanupClient()

        with patch(
            "lib.imapwatch.checker.imapclient.IMAPClient", return_value=cleanup
        ) as imap_client:
            checker.post_process([101, 102])

        imap_client.assert_called_once_with(
            "imap.example.test", ssl=False, ssl_context=None, use_uid=True
        )
        self.assertIn(call.remove_flags([101, 102], [b"\\Flagged"]), cleanup.calls)
        self.assertNotIn(call.move([101, 102], "Archive"), cleanup.calls)
        self.assertTrue(cleanup.logged_out)

    def test_archive_only(self):
        checker = make_checker(archive_after_processing="Archive")
        cleanup = CleanupClient()

        with patch(
            "lib.imapwatch.checker.imapclient.IMAPClient", return_value=cleanup
        ):
            checker.post_process([201])

        self.assertEqual(
            cleanup.calls,
            [
                call.login("user", "password"),
                call.select_folder("INBOX"),
                call.has_capability("MOVE"),
                call.folder_exists("Archive"),
                call.move([201], "Archive"),
            ],
        )
        self.assertTrue(cleanup.logged_out)

    def test_remove_flag_then_archive(self):
        checker = make_checker(
            remove_flag_after_processing=True,
            archive_after_processing="Archive",
        )
        cleanup = CleanupClient()

        with patch(
            "lib.imapwatch.checker.imapclient.IMAPClient", return_value=cleanup
        ):
            checker.post_process([301, 302])

        self.assertLess(
            cleanup.calls.index(call.remove_flags([301, 302], [b"\\Flagged"])),
            cleanup.calls.index(call.move([301, 302], "Archive")),
        )

    def test_unsupported_move_leaves_flags_untouched(self):
        checker = make_checker(
            remove_flag_after_processing=True,
            archive_after_processing="Archive",
        )
        cleanup = CleanupClient(supports_move=False)

        with patch(
            "lib.imapwatch.checker.imapclient.IMAPClient", return_value=cleanup
        ):
            checker.post_process([401])

        self.assertNotIn(call.remove_flags([401], [b"\\Flagged"]), cleanup.calls)
        self.assertNotIn(call.move([401], "Archive"), cleanup.calls)
        self.assertTrue(cleanup.logged_out)

    def test_missing_archive_leaves_flags_untouched(self):
        checker = make_checker(
            remove_flag_after_processing=True,
            archive_after_processing="Missing",
        )
        cleanup = CleanupClient(archive_exists=False)

        with patch(
            "lib.imapwatch.checker.imapclient.IMAPClient", return_value=cleanup
        ):
            checker.post_process([501])

        self.assertNotIn(call.remove_flags([501], [b"\\Flagged"]), cleanup.calls)
        self.assertNotIn(call.move([501], "Missing"), cleanup.calls)
        self.assertTrue(cleanup.logged_out)

    def test_connection_failure_is_logged_without_raising(self):
        checker = make_checker(remove_flag_after_processing=True)

        with patch(
            "lib.imapwatch.checker.imapclient.IMAPClient",
            side_effect=imapclient.exceptions.IMAPClientError("offline"),
        ):
            checker.post_process([601])

        checker.logger.error.assert_called_once()

    def test_move_failure_logs_partial_cleanup(self):
        checker = make_checker(
            remove_flag_after_processing=True,
            archive_after_processing="Archive",
        )
        cleanup = CleanupClient(
            move_error=imapclient.exceptions.IMAPClientError("move failed")
        )

        with patch(
            "lib.imapwatch.checker.imapclient.IMAPClient", return_value=cleanup
        ):
            checker.post_process([701])

        log_message = checker.logger.error.call_args.args[0]
        self.assertIn("flags were removed", log_message)
        self.assertTrue(cleanup.logged_out)


class CheckerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.watch = IMAPWatch.__new__(IMAPWatch)
        self.watch.logger = Mock()
        self.watch.stop_event = threading.Event()
        self.account = {
            "server": "imap.example.test",
            "username": "user",
            "password": "password",
            "use_ssl": True,
            "timeout": 15,
        }
        self.action = {"action": "things", "email": "things@example.test"}

    def test_mailbox_options_are_passed_to_checker(self):
        mailbox = {
            "mailbox": "INBOX",
            "check_for": ["flagged"],
            "remove_flag_after_processing": True,
            "archive_after_processing": "Archive",
        }

        checker = self.watch.create_checker(
            self.account, mailbox, self.action, sender=Mock()
        )

        self.assertTrue(checker.remove_flag_after_processing)
        self.assertEqual(checker.archive_after_processing, "Archive")

    def test_mailbox_options_default_to_disabled(self):
        mailbox = {"mailbox": "INBOX", "check_for": ["flagged"]}

        checker = self.watch.create_checker(
            self.account, mailbox, self.action, sender=Mock()
        )

        self.assertFalse(checker.remove_flag_after_processing)
        self.assertIsNone(checker.archive_after_processing)


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
