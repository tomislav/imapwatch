import smtplib
import threading
import logging
from email.mime.text import MIMEText
from email.header import Header


class Sender:
    def __init__(self, logger, server, username, password, from_):
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
        s.login(self.username, self.password)
        s.sendmail(self.from_, to, msg.as_string())
        s.quit()


class SenderThread(threading.Thread):
    def __init__(self, name, logger, sender: Sender, to, subject, body):
        self.logger = logger
        self.sender = sender
        self.to = to
        self.subject = subject
        self.body = body
        threading.Thread.__init__(self, name=name)

    def run(self):
        self.sender.send(self.to, self.subject, self.body)

    def stop(self):
        self.sender.stop()
