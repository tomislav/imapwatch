import logging
import unittest
from unittest.mock import Mock, call, patch

from lib.imapwatch.sender import Sender, SenderThread


class SenderTests(unittest.TestCase):
    def test_sends_without_login_when_credentials_are_omitted(self):
        smtp = Mock()
        sender = Sender(
            Mock(),
            "smtp.example.test",
            username=None,
            password=None,
            from_="imapwatch@example.test",
        )

        with patch("lib.imapwatch.sender.smtplib.SMTP", return_value=smtp) as client:
            sender.send("to@example.test", "Subject", "Body")

        client.assert_called_once_with("smtp.example.test", 587)
        smtp.ehlo.assert_called_once()
        smtp.starttls.assert_called_once()
        smtp.login.assert_not_called()
        smtp.sendmail.assert_called_once()
        smtp.quit.assert_called_once()

    def test_existing_credentials_are_used_for_login(self):
        smtp = Mock()
        sender = Sender(
            Mock(),
            "smtp.example.test",
            username="user",
            password="password",
            from_="imapwatch@example.test",
        )

        with patch("lib.imapwatch.sender.smtplib.SMTP", return_value=smtp):
            sender.send("to@example.test", "Subject", "Body")

        smtp.login.assert_called_once_with("user", "password")
        smtp.sendmail.assert_called_once()

    def test_partial_credentials_fail_before_sending(self):
        with self.assertRaisesRegex(ValueError, "both be set or both be omitted"):
            Sender(
                Mock(),
                "smtp.example.test",
                username="user",
                password=None,
                from_="imapwatch@example.test",
            )


class SenderThreadTests(unittest.TestCase):
    def test_delivery_logs_context_and_keeps_content_at_debug(self):
        logger = Mock()
        sender = Mock(from_="imapwatch@example.test")
        context = {
            "account": "provider",
            "mailbox": "INBOX",
            "action": "things",
            "count": 1,
            "uids": [42],
        }
        thread = SenderThread(
            "smtp:provider:INBOX",
            logger,
            sender,
            "things@example.test",
            "Review proposal",
            "Private body",
            context=context,
        )

        with patch(
            "lib.imapwatch.sender.time.monotonic", side_effect=[5.0, 5.391]
        ):
            thread.run()

        self.assertEqual(
            logger.info.call_args_list,
            [
                call(
                    "event=smtp_send_started account=provider mailbox=INBOX "
                    "action=things count=1 uids=[42]"
                ),
                call(
                    "event=smtp_send_succeeded account=provider mailbox=INBOX "
                    "action=things count=1 uids=[42] duration_ms=391"
                ),
            ],
        )
        info_text = " ".join(item.args[0] for item in logger.info.call_args_list)
        self.assertNotIn("things@example.test", info_text)
        self.assertNotIn("Review proposal", info_text)
        self.assertNotIn("Private body", info_text)
        logger.debug.assert_called_once_with(
            "event=smtp_send_content account=provider mailbox=INBOX "
            "action=things count=1 uids=[42] "
            "from_address=imapwatch@example.test destination=things@example.test "
            'title="Review proposal"'
        )
        self.assertNotIn("Private body", logger.debug.call_args.args[0])

    def test_success_callback_runs_after_delivery(self):
        events = []
        sender = Mock()
        sender.send.side_effect = lambda *args: events.append("sent")
        callback = lambda: events.append("post-processed")
        thread = SenderThread(
            "Sender",
            logging.getLogger(self.id()),
            sender,
            "to@example.test",
            "Subject",
            "Body",
            on_success=callback,
        )

        thread.run()

        self.assertEqual(events, ["sent", "post-processed"])

    def test_delivery_failure_does_not_run_callback(self):
        logger = Mock()
        sender = Mock()
        sender.send.side_effect = RuntimeError("SMTP unavailable")
        callback = Mock()
        thread = SenderThread(
            "Sender",
            logger,
            sender,
            "to@example.test",
            "Subject",
            "Body",
            on_success=callback,
        )

        thread.run()

        callback.assert_not_called()
        logger.error.assert_called_once()
        error_message = logger.error.call_args.args[0]
        self.assertIn("event=smtp_send_failed", error_message)
        self.assertIn("error_type=RuntimeError", error_message)
        self.assertNotIn("to@example.test", error_message)
        self.assertNotIn("Subject", error_message)
        self.assertNotIn("SMTP unavailable", error_message)
        debug_text = " ".join(item.args[0] for item in logger.debug.call_args_list)
        self.assertIn("to@example.test", debug_text)
        self.assertIn("SMTP unavailable", debug_text)

    def test_callback_failure_is_contained(self):
        logger = Mock()
        callback = Mock(side_effect=RuntimeError("cleanup failed"))
        thread = SenderThread(
            "Sender",
            logger,
            Mock(),
            "to@example.test",
            "Subject",
            "Body",
            on_success=callback,
        )

        thread.run()

        callback.assert_called_once()
        logger.error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
