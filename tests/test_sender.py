import logging
import unittest
from unittest.mock import Mock

from lib.imapwatch.sender import SenderThread


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
