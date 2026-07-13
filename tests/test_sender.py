import logging
import unittest
from unittest.mock import Mock, patch

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
