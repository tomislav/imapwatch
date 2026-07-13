# /usr/bin/env python3
import datetime
import imaplib
import socket
import ssl
import threading
import time
import imapclient
import imapclient.exceptions
import email
from email.header import decode_header
from urllib.parse import quote_plus
from .sender import Sender, SenderThread


class Checker:
    def __init__(
        self,
        logger,
        stop_event,
        server_address: str,
        username,
        password,
        mailbox,
        check_for,
        action,
        sender,
        use_ssl=True,
        timeout=10,
        remove_flag_after_processing=False,
        archive_after_processing=None,
    ):
        (
            self.server,
            self.ssl_context,
        ) = (
            None,
            None,
        )
        self.logger = logger
        self.stop_event = stop_event
        self.server_address = server_address
        self.username = username
        self.password = password
        self.timeout = timeout
        self.mailbox = mailbox
        self.check_for = check_for
        self.action = action
        self.sender = sender
        self.use_ssl = use_ssl
        self.remove_flag_after_processing = remove_flag_after_processing
        self.archive_after_processing = archive_after_processing
        self.connected = False
        self.last_activity = 0
        if use_ssl:
            self.ssl_context = ssl.create_default_context()
        self.last_sync = datetime.datetime.now()

    def connect(self):
        self.server = imapclient.IMAPClient(
            self.server_address,
            ssl=self.use_ssl,
            ssl_context=self.ssl_context,
            use_uid=False,
        )
        self.server.login(self.username, self.password)
        self.server.select_folder(self.mailbox)
        self.connected = True
        self.last_activity = time.time()
        self.logger.info(f"Connected to mailbox {self.mailbox}")

    def timestamps_difference(self, timestamp):
        delta = timestamp - self.last_sync
        return delta.days * 24 * 60 + (delta.seconds + delta.microseconds / 10e6) / 60

    def check_messages(self, responses):
        """
        Parse IDLE responses into a list of message sequence numbers
        that we should process, based on self.check_for (['flagged'], ['new'], or both).
        """
        messages = []

        for r in responses:
            if not isinstance(r, (list, tuple)) or len(r) < 2:
                continue

            msg_num = r[0]
            resp_type = r[1]

            # Normalise resp_type to bytes for comparison
            if isinstance(resp_type, str):
                resp_type_b = resp_type.encode()
            else:
                resp_type_b = resp_type

            # 1) New messages: "* n EXISTS"
            if "new" in self.check_for and resp_type_b == b"EXISTS":
                messages.append(msg_num)

            # 2) Flag changes: "* n FETCH (FLAGS (...))"
            if "flagged" in self.check_for and resp_type_b == b"FETCH" and len(r) >= 3:
                data = r[2]

                # imapclient often returns something like:
                # (b'UID', 513, b'FLAGS', (b'\\Seen', b'\\Flagged'))
                if isinstance(data, (list, tuple)):
                    flags_tuple = None

                    # find the FLAGS element in the structured tuple
                    for i in range(len(data) - 1):
                        key = data[i]
                        value = data[i + 1]

                        if isinstance(key, bytes):
                            key_b = key
                        else:
                            key_b = key.encode() if isinstance(key, str) else None

                        if key_b == b"FLAGS" and isinstance(value, (list, tuple)):
                            flags_tuple = value
                            break

                    if flags_tuple:
                        # Normalise flags to bytes and check for \Flagged without \Deleted
                        flags_bytes = []
                        for f in flags_tuple:
                            if isinstance(f, bytes):
                                flags_bytes.append(f)
                            elif isinstance(f, str):
                                flags_bytes.append(f.encode())

                        has_flagged = any(b"\\Flagged" in f for f in flags_bytes)
                        has_deleted = any(b"\\Deleted" in f for f in flags_bytes)

                        if has_flagged and not has_deleted:
                            messages.append(msg_num)

        # De-duplicate while preserving order
        seen = set()
        deduped = []
        for m in messages:
            if m not in seen:
                deduped.append(m)
                seen.add(m)

        return deduped

    def decode_header(self, header):
        h = email.header.decode_header(header.decode())
        # self.logger.debug(f"h: {h}")
        # elements = [ i[0].decode(i[1]) if i[1] else i[0] for i in h ]
        elements = []
        for i in h:
            if i[1]:
                elements.append(i[0].decode(i[1]))
            else:
                try:
                    elements.append(i[0].decode())
                except AttributeError:
                    elements.append(i[0])
        # TODO should we join with a space or no space?
        return "".join(elements)

    def fetch_messages(self, messages):
        items = []
        if not messages:
            return items

        fetch_result = self.server.fetch(messages, ["ENVELOPE", "UID"])
        for fetch_id, data in fetch_result.items():
            if b"ENVELOPE" not in data:
                self.logger.warning(
                    f"{self.mailbox}: missing ENVELOPE for message {fetch_id}, data keys={list(data.keys())}"
                )
                continue

            envelope = data[b"ENVELOPE"]
            # message-id can be None
            message_id = (
                envelope.message_id.decode()
                if envelope.message_id is not None
                else ""
            )

            subject = (
                self.decode_header(envelope.subject).strip()
                if envelope.subject is not None
                else ""
            )

            if envelope.from_ and envelope.from_[0].name:
                from_ = self.decode_header(envelope.from_[0].name).strip()
            elif envelope.from_:
                from_ = (
                    envelope.from_[0].mailbox + b"@" + envelope.from_[0].host
                ).decode()
            else:
                from_ = ""

            items.append(
                {
                    "from_": from_,
                    "subject": subject,
                    "message_id": message_id,
                    "uid": data.get(b"UID"),
                }
            )
            self.logger.info(f"Flagged item: {from_} / {subject}")

        return items

    def dispatch(self, items):
        uids = [item["uid"] for item in items if item.get("uid") is not None]

        if self.action["action"] == "things":
            subject = items[0]["subject"]
            items.reverse()
            body = "\n\n".join(
                [
                    f'\u2709\ufe0f {i["from_"]}: "{i["subject"]}"\nmessage:{quote_plus(i["message_id"])}'
                    for i in items
                ]
            )

        elif self.action["action"] == "omnifocus":
            subject = items[0]["subject"]
            items.reverse()
            body = "\n\n".join(
                [
                    f'\u2709\ufe0f {i["from_"]}: "{i["subject"]}"\nmessage:{quote_plus(i["message_id"])}'
                    for i in items
                ]
            )

        # TODO: create this action
        elif self.action["action"] == "resend":
            body = "Test resend"
            subject = items[0]["subject"]

        on_success = None
        if self.remove_flag_after_processing or self.archive_after_processing:
            on_success = lambda: self.post_process(uids)

        SenderThread(
            "Sender",
            self.logger,
            self.sender,
            self.action["email"],
            subject,
            body,
            on_success=on_success,
        ).start()

    def post_process(self, uids):
        """Apply configured post-processing using a dedicated UID connection."""
        if not uids or not (
            self.remove_flag_after_processing or self.archive_after_processing
        ):
            return

        cleanup_server = None
        flag_removed = False
        try:
            cleanup_server = imapclient.IMAPClient(
                self.server_address,
                ssl=self.use_ssl,
                ssl_context=self.ssl_context,
                use_uid=True,
            )
            cleanup_server.login(self.username, self.password)
            cleanup_server.select_folder(self.mailbox)

            if self.archive_after_processing:
                if not cleanup_server.has_capability("MOVE"):
                    self.logger.error(
                        f"{self.mailbox}: cannot archive processed messages because "
                        "the server does not support MOVE"
                    )
                    return
                if not cleanup_server.folder_exists(self.archive_after_processing):
                    self.logger.error(
                        f"{self.mailbox}: cannot archive processed messages because "
                        f"folder {self.archive_after_processing!r} does not exist"
                    )
                    return

            if self.remove_flag_after_processing:
                cleanup_server.remove_flags(uids, [b"\\Flagged"])
                flag_removed = True

            if self.archive_after_processing:
                cleanup_server.move(uids, self.archive_after_processing)

            operations = []
            if self.remove_flag_after_processing:
                operations.append("removed flag")
            if self.archive_after_processing:
                operations.append(f"archived to {self.archive_after_processing!r}")
            self.logger.info(
                f"{self.mailbox}: post-processed messages {uids}: "
                f"{', '.join(operations)}"
            )
        except Exception as exception:
            partial = ""
            if flag_removed and self.archive_after_processing:
                partial = "; flags were removed before the archive operation failed"
            self.logger.error(
                f"{self.mailbox}: failed to post-process messages {uids}: "
                f"{exception}{partial}",
                exc_info=True,
            )
        finally:
            if cleanup_server is not None:
                try:
                    cleanup_server.logout()
                except Exception:
                    try:
                        cleanup_server.shutdown()
                    except Exception:
                        pass

    def idle_loop(self):
        """Main loop: maintain an IDLE connection and react to events."""
        # we keep running until stop_event is set
        while not self.stop_event.is_set():
            try:
                # Connect here, inside the recovery boundary.  A reconnect can fail
                # too (for example while the IMAP server is returning an internal
                # error), and must not be allowed to terminate the checker thread.
                if self.server is None:
                    self.connect()

                self.logger.debug(f"Starting IDLE for {self.mailbox}")
                self.server.idle()
                self.last_sync = datetime.datetime.now()

                while not self.stop_event.is_set():
                    current_sync = datetime.datetime.now()

                    # Wait for untagged responses (new mail, flag changes, etc.)
                    responses = self.server.idle_check(timeout=10)
                    self.last_activity = time.time()
                    self.logger.debug(f"{self.mailbox}: IDLE responses: {responses}")

                    if isinstance(responses, list) and len(responses) > 0:
                        messages = self.check_messages(responses)
                        if messages:
                            self.logger.info(
                                f"{self.mailbox}: processing messages {messages}"
                            )
                            # Leave IDLE mode so we can FETCH
                            try:
                                self.server.idle_done()
                            except Exception:
                                # best effort – if we're already out of IDLE, just continue
                                pass

                            items = self.fetch_messages(messages)
                            self.last_activity = time.time()
                            if items:
                                self.dispatch(items)

                            # Go back to IDLE
                            self.server.noop()
                            self.last_activity = time.time()
                            self.server.idle()
                            self.last_sync = current_sync

                    # Periodically refresh IDLE so servers don’t kill us silently
                    if self.timestamps_difference(current_sync) > self.timeout:
                        self.logger.debug("Refreshing IDLE timeout")
                        try:
                            self.server.idle_done()
                        except Exception:
                            pass
                        self.server.noop()
                        self.last_activity = time.time()
                        self.server.idle()
                        self.last_sync = current_sync

            except (
                imapclient.exceptions.IMAPClientError,
                imapclient.exceptions.IMAPClientAbortError,
                imaplib.IMAP4.error,
                imaplib.IMAP4.abort,
                socket.error,
                socket.timeout,
                ssl.SSLError,
                ssl.SSLEOFError,
            ) as exception:
                self.connected = False
                self.logger.critical(
                    f"Checker: Got exception @ {self.mailbox}: {exception}"
                )

                if self.stop_event.is_set():
                    break

                self.logger.info("Reconnecting in 5 seconds…")

                # best-effort cleanup of the old connection
                if self.server is not None:
                    try:
                        self.server.idle_done()
                    except Exception:
                        pass
                    try:
                        self.server.logout()
                    except Exception:
                        pass
                self.server = None

                # Event.wait makes shutdown immediate instead of making it wait for
                # the entire reconnect delay.
                if self.stop_event.wait(5):
                    break
                continue

        # Clean shutdown
        if self.server is not None:
            try:
                self.server.idle_done()
            except Exception:
                pass
            try:
                self.server.logout()
            except Exception:
                pass
        self.connected = False
        self.server = None

    def stop(self):
        self.stop_event.set()


class CheckerThread(threading.Thread):
    def __init__(self, logger, checker: Checker):
        self.logger = logger
        self.checker = checker
        threading.Thread.__init__(self, name=checker.mailbox)

    def run(self):
        self.checker.idle_loop()

    def stop(self):
        self.checker.stop()
