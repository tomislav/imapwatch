import smtplib
import threading
from email.mime.text import MIMEText


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
        self.logger.debug(f"Sending message now: {self.from_} => {to}: {subject}")
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
        self, name, logger, sender: Sender, to, subject, body, on_success=None
    ):
        self.logger = logger
        self.sender = sender
        self.to = to
        self.subject = subject
        self.body = body
        self.on_success = on_success
        threading.Thread.__init__(self, name=name)

    def run(self):
        try:
            self.sender.send(self.to, self.subject, self.body)
        except Exception as exception:
            self.logger.error(
                f"Failed to send message to {self.to}: {exception}", exc_info=True
            )
            return

        if self.on_success is not None:
            try:
                self.on_success()
            except Exception as exception:
                self.logger.error(
                    f"Post-send callback failed for {self.to}: {exception}",
                    exc_info=True,
                )

    def stop(self):
        self.sender.stop()
