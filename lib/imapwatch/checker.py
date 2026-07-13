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
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
import re
from urllib.parse import quote_plus
from .logging_utils import log_event
from .sender import SenderThread


class _HTMLTextExtractor(HTMLParser):
    block_tags = {
        "br",
        "div",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "li",
        "p",
        "table",
        "td",
        "th",
        "tr",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden_depth += 1
        elif tag in self.block_tags:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1
        elif tag in self.block_tags:
            self.parts.append(" ")

    def handle_data(self, data):
        if not self.hidden_depth:
            self.parts.append(data)

    def text(self):
        return "".join(self.parts)


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
        title_generator=None,
        account="account-1",
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
        self.account = account
        self.mailbox = mailbox
        self.check_for = check_for
        self.action = action
        self.action_name = action["action"]
        self.sender = sender
        self.use_ssl = use_ssl
        self.remove_flag_after_processing = remove_flag_after_processing
        self.archive_after_processing = archive_after_processing
        self.title_generator = title_generator
        self.connected = False
        self.last_activity = 0
        self.reconnect_attempts = 0
        if use_ssl:
            self.ssl_context = ssl.create_default_context()
        self.last_sync = datetime.datetime.now()

    def log(self, level, event, *, exc_info=False, **fields):
        log_event(
            self.logger,
            level,
            event,
            exc_info=exc_info,
            account=self.account,
            mailbox=self.mailbox,
            action=self.action_name,
            **fields,
        )

    def connect(self):
        started_at = time.monotonic()
        reconnect_attempt = self.reconnect_attempts or None
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
        self.reconnect_attempts = 0
        self.log(
            "info",
            "mailbox_connected",
            server=self.server_address,
            use_ssl=self.use_ssl,
            reconnect_attempt=reconnect_attempt,
            duration_ms=round((time.monotonic() - started_at) * 1000),
        )

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

        fetch_fields = ["ENVELOPE", "UID"]
        if self.title_generator is not None:
            fetch_fields.append("BODY.PEEK[]")
        fetch_result = self.server.fetch(messages, fetch_fields)
        for fetch_id, data in fetch_result.items():
            if b"ENVELOPE" not in data:
                self.log(
                    "warning",
                    "message_fetch_failed",
                    sequence_number=fetch_id,
                    error_type="MissingEnvelope",
                    data_keys=[
                        key.decode(errors="replace")
                        if isinstance(key, bytes)
                        else str(key)
                        for key in data.keys()
                    ],
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

            item = {
                "from_": from_,
                "subject": subject,
                "message_id": message_id,
                "uid": data.get(b"UID"),
            }
            if self.title_generator is not None:
                item["body"] = self.extract_body(data.get(b"BODY[]"))
            items.append(item)
            self.log(
                "debug",
                "message_fetched",
                sequence_number=fetch_id,
                uid=item["uid"],
                sender=from_,
                subject=subject,
            )

        return items

    @staticmethod
    def _normalise_body(value):
        return re.sub(r"\s+", " ", value).strip()

    @staticmethod
    def _decode_part(part):
        try:
            content = part.get_content()
            if isinstance(content, str):
                return content
        except (LookupError, UnicodeDecodeError):
            pass

        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")

    def extract_body(self, raw_message):
        if not isinstance(raw_message, bytes):
            return ""
        try:
            message = BytesParser(policy=policy.default).parsebytes(raw_message)
        except Exception as exception:
            self.log(
                "warning",
                "message_body_parse_failed",
                error_type=type(exception).__name__,
            )
            return ""

        plain_parts = []
        html_parts = []

        def collect_parts(part):
            # Skip the entire subtree for attached files and attached messages.
            if part.get_content_disposition() == "attachment" or part.get_filename():
                return
            if part.is_multipart():
                for child in part.iter_parts():
                    collect_parts(child)
                return

            content_type = part.get_content_type()
            if content_type not in {"text/plain", "text/html"}:
                return
            content = self._decode_part(part)
            if content_type == "text/plain":
                plain_parts.append(content)
            else:
                html_parts.append(content)

        collect_parts(message)

        if plain_parts:
            return self._normalise_body(" ".join(plain_parts))
        if not html_parts:
            return ""

        parser = _HTMLTextExtractor()
        try:
            parser.feed(" ".join(html_parts))
            parser.close()
        except Exception as exception:
            self.log(
                "warning",
                "message_html_conversion_failed",
                error_type=type(exception).__name__,
            )
            return ""
        return self._normalise_body(parser.text())

    def dispatch(self, items):
        uids = [item["uid"] for item in items if item.get("uid") is not None]
        title_source = "subject"

        if self.action["action"] in {"things", "omnifocus"}:
            subject = items[0]["subject"]
            body = "\n\n".join(
                [
                    f'\u2709\ufe0f {i["from_"]}: "{i["subject"]}"\nmessage:{quote_plus(i["message_id"])}'
                    for i in reversed(items)
                ]
            )
            if self.title_generator is not None:
                try:
                    generated_title = self.title_generator.generate(
                        items,
                        account=self.account,
                        mailbox=self.mailbox,
                        action=self.action_name,
                    )
                except Exception as exception:
                    self.log(
                        "warning",
                        "openai_title_failed",
                        error_type=type(exception).__name__,
                        fallback="original_subject",
                    )
                    generated_title = None
                if generated_title:
                    subject = generated_title
                    title_source = "openai"

        # TODO: create this action
        elif self.action["action"] == "resend":
            body = "Test resend"
            subject = items[0]["subject"]

        on_success = None
        if self.remove_flag_after_processing or self.archive_after_processing:
            on_success = lambda: self.post_process(uids)

        self.log(
            "info",
            "dispatch_started",
            count=len(items),
            uids=uids,
            title_source=title_source,
        )
        self.log(
            "debug",
            "dispatch_content",
            destination=self.action["email"],
            title=subject,
        )

        SenderThread(
            f"smtp:{self.account}:{self.mailbox}",
            self.logger,
            self.sender,
            self.action["email"],
            subject,
            body,
            on_success=on_success,
            context={
                "account": self.account,
                "mailbox": self.mailbox,
                "action": self.action_name,
                "count": len(items),
                "uids": uids,
            },
        ).start()

    def post_process(self, uids):
        """Apply configured post-processing using a dedicated UID connection."""
        if not uids or not (
            self.remove_flag_after_processing or self.archive_after_processing
        ):
            return

        started_at = time.monotonic()
        cleanup_server = None
        flag_removed = False
        archive_strategy = None
        fallback_stage = None
        copied = False
        source_deleted = False
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
                if not cleanup_server.folder_exists(self.archive_after_processing):
                    self.log(
                        "error",
                        "post_process_failed",
                        uids=uids,
                        archive_folder=self.archive_after_processing,
                        duration_ms=round(
                            (time.monotonic() - started_at) * 1000
                        ),
                        error_type="MissingArchiveFolder",
                    )
                    return
                if cleanup_server.has_capability("MOVE"):
                    archive_strategy = "move"
                elif cleanup_server.has_capability("UIDPLUS"):
                    archive_strategy = "copy-delete"
                else:
                    self.log(
                        "error",
                        "post_process_failed",
                        uids=uids,
                        archive_folder=self.archive_after_processing,
                        duration_ms=round(
                            (time.monotonic() - started_at) * 1000
                        ),
                        error_type="UnsupportedArchiveStrategy",
                    )
                    return

            if self.remove_flag_after_processing:
                cleanup_server.remove_flags(uids, [b"\\Flagged"])
                flag_removed = True

            if self.archive_after_processing:
                if archive_strategy == "move":
                    fallback_stage = "MOVE"
                    cleanup_server.move(uids, self.archive_after_processing)
                else:
                    fallback_stage = "COPY"
                    cleanup_server.copy(uids, self.archive_after_processing)
                    copied = True

                    fallback_stage = "marking source messages deleted"
                    cleanup_server.delete_messages(uids, silent=True)
                    source_deleted = True

                    fallback_stage = "UID EXPUNGE"
                    cleanup_server.uid_expunge(uids)

            operations = []
            if self.remove_flag_after_processing:
                operations.append("remove_flag")
            if self.archive_after_processing:
                operations.append("archive")
            self.log(
                "info",
                "post_process_succeeded",
                uids=uids,
                operations=operations,
                archive_folder=self.archive_after_processing,
                archive_strategy=archive_strategy,
                duration_ms=round((time.monotonic() - started_at) * 1000),
            )
        except Exception as exception:
            partial_states = []
            if flag_removed and self.archive_after_processing:
                partial_states.append("flags were removed")
            if copied:
                partial_states.append("an archive copy exists")
            if source_deleted:
                partial_states.append("the source remains marked \\Deleted")
            elif copied:
                partial_states.append("the source remains in the watched mailbox")

            self.log(
                "error",
                "post_process_failed",
                exc_info=True,
                uids=uids,
                stage=fallback_stage,
                partial_state=partial_states or None,
                archive_folder=self.archive_after_processing,
                archive_strategy=archive_strategy,
                duration_ms=round((time.monotonic() - started_at) * 1000),
                error_type=type(exception).__name__,
                error=str(exception),
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

    @staticmethod
    def _response_types(responses):
        response_types = []
        if not isinstance(responses, list):
            return response_types
        for response in responses:
            if not isinstance(response, (list, tuple)) or len(response) < 2:
                response_types.append(type(response).__name__)
                continue
            response_type = response[1]
            if isinstance(response_type, bytes):
                response_type = response_type.decode(errors="replace")
            response_types.append(str(response_type))
        return response_types

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

                self.log("debug", "idle_started")
                self.server.idle()
                self.last_sync = datetime.datetime.now()

                while not self.stop_event.is_set():
                    current_sync = datetime.datetime.now()

                    # Wait for untagged responses (new mail, flag changes, etc.)
                    responses = self.server.idle_check(timeout=10)
                    self.last_activity = time.time()
                    self.log(
                        "debug",
                        "idle_responses",
                        count=len(responses) if isinstance(responses, list) else 0,
                        response_types=self._response_types(responses),
                    )

                    if isinstance(responses, list) and len(responses) > 0:
                        messages = self.check_messages(responses)
                        if messages:
                            self.log(
                                "info",
                                "messages_detected",
                                count=len(messages),
                                sequence_numbers=messages,
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
                        self.log("debug", "idle_refreshed")
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
                self.reconnect_attempts += 1
                self.log(
                    "warning",
                    "imap_connection_lost",
                    retry_in_seconds=5,
                    reconnect_attempt=self.reconnect_attempts,
                    error_type=type(exception).__name__,
                    error=str(exception),
                )

                if self.stop_event.is_set():
                    break

                self.log(
                    "info",
                    "reconnect_scheduled",
                    retry_in_seconds=5,
                    reconnect_attempt=self.reconnect_attempts,
                )

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
        self.log("info", "mailbox_disconnected", reason="shutdown")

    def stop(self):
        self.stop_event.set()


class CheckerThread(threading.Thread):
    def __init__(self, logger, checker: Checker):
        self.logger = logger
        self.checker = checker
        threading.Thread.__init__(
            self, name=f"imap:{checker.account}:{checker.mailbox}"
        )

    def run(self):
        self.checker.idle_loop()

    def stop(self):
        self.checker.stop()
