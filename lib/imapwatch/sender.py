import smtplib
import threading
import time
from email.mime.text import MIMEText

from .logging_utils import log_event


class Sender:
    def __init__(self, logger, server, username, password, from_):
        if bool(username) != bool(password):
            raise ValueError(
                "SMTP username and password must either both be set or both be omitted"
            )
        self.logger = logger
        self.server = server
        self.username = username
        self.password = password
        self.from_ = from_
        threading.Thread.__init__(self)

    def send(self, to, subject, message):
        # construct to, from, subject
        msg = MIMEText(message, "plain", "utf-8")
        msg["From"] = self.from_
        msg["To"] = to
        msg["Subject"] = subject

        s = smtplib.SMTP(self.server, 587)
        s.ehlo()
        s.starttls()
        if self.username:
            s.login(self.username, self.password)
        s.sendmail(self.from_, to, msg.as_string())
        s.quit()


class SenderThread(threading.Thread):
    def __init__(
        self,
        name,
        logger,
        sender: Sender,
        to,
        subject,
        body,
        on_success=None,
        context=None,
    ):
        self.logger = logger
        self.sender = sender
        self.to = to
        self.subject = subject
        self.body = body
        self.on_success = on_success
        self.context = context or {}
        threading.Thread.__init__(self, name=name)

    def run(self):
        started_at = time.monotonic()
        log_event(self.logger, "info", "smtp_send_started", **self.context)
        log_event(
            self.logger,
            "debug",
            "smtp_send_content",
            **self.context,
            from_address=self.sender.from_,
            destination=self.to,
            title=self.subject,
        )
        try:
            self.sender.send(self.to, self.subject, self.body)
        except Exception as exception:
            log_event(
                self.logger,
                "error",
                "smtp_send_failed",
                **self.context,
                duration_ms=round((time.monotonic() - started_at) * 1000),
                error_type=type(exception).__name__,
            )
            log_event(
                self.logger,
                "debug",
                "smtp_send_error",
                exc_info=True,
                **self.context,
                destination=self.to,
                error=str(exception),
            )
            return

        log_event(
            self.logger,
            "info",
            "smtp_send_succeeded",
            **self.context,
            duration_ms=round((time.monotonic() - started_at) * 1000),
        )

        if self.on_success is not None:
            try:
                self.on_success()
            except Exception as exception:
                log_event(
                    self.logger,
                    "error",
                    "post_process_failed",
                    **self.context,
                    stage="callback",
                    error_type=type(exception).__name__,
                )
                log_event(
                    self.logger,
                    "debug",
                    "post_process_error",
                    exc_info=True,
                    **self.context,
                    stage="callback",
                    destination=self.to,
                    error=str(exception),
                )

    def stop(self):
        self.sender.stop()
