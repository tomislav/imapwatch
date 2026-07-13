import unittest
from unittest.mock import Mock

from lib.imapwatch.logging_utils import format_event, log_event


class LoggingUtilsTests(unittest.TestCase):
    def test_format_event_uses_searchable_fields_and_quotes_whitespace(self):
        self.assertEqual(
            format_event(
                "message_fetched",
                account="provider",
                mailbox="Project Mail",
                enabled=True,
                count=2,
                uids=[10, 11],
                optional=None,
            ),
            'event=message_fetched account=provider mailbox="Project Mail" '
            "enabled=true count=2 uids=[10,11]",
        )

    def test_log_event_only_adds_traceback_when_requested(self):
        logger = Mock()

        log_event(logger, "warning", "retry", attempt=1)
        log_event(logger, "error", "failed", exc_info=True, error_type="Error")

        logger.warning.assert_called_once_with("event=retry attempt=1")
        logger.error.assert_called_once_with(
            "event=failed error_type=Error", exc_info=True
        )


if __name__ == "__main__":
    unittest.main()
