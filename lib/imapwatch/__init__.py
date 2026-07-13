__all__ = [
    "checker",
    "sender",
    "title_generator",
    "logging_utils",
    "filelikelogger",
    "loggingdaemoncontext",
]

import time
import logging
import json
import yaml
import threading
import daemon
import sys
import os
import signal
from logging.handlers import RotatingFileHandler
from daemon.pidfile import TimeoutPIDLockFile
from lockfile import AlreadyLocked, LockTimeout, NotLocked
from .sender import Sender
from .checker import Checker, CheckerThread
from .logging_utils import log_event
from .loggingdaemoncontext import LoggingDaemonContext
from .title_generator import OpenAITitleGenerator


class IMAPWatch:
    def __init__(
        self,
        basedir=None,
        configfile="imapwatch.yml",
        pidfile="/tmp/imapwatch.pid",
        logfile="log/imapwatch.log",
        daemon=False,
        verbose=None,
        force=False,
        healthfile="/tmp/imapwatch.health",
    ):
        if basedir:
            # basedir must be a full, absolute path
            __location__ = os.path.realpath(os.path.join(basedir))
        else:
            # assume the configfile and log are in the parent-parent directory of the directory of this file
            __location__ = os.path.realpath(
                os.path.join(
                    os.getcwd(),
                    os.path.dirname(os.path.realpath(__file__)),
                    os.pardir,
                    os.pardir,
                )
            )

        configfile = os.path.join(__location__, configfile)
        # Use SafeLoader for secure loading
        self.config = yaml.load(open(configfile, "r"), Loader=yaml.SafeLoader)
        if not self.config:
            raise SystemExit("No config file found. Exiting.")

        self.pidfile = TimeoutPIDLockFile(pidfile, timeout=1)
        self.healthfile = healthfile
        self.logfile = os.path.join(__location__, logfile)
        self.daemon = daemon
        self.verbose = verbose
        self.force = force

        self.stop_event = threading.Event()
        self.threads = []

    def write_health(self):
        """Atomically publish application health for the external status command."""
        now = time.time()
        checker_states = []
        for thread in self.threads:
            checker = thread.checker
            thread_alive = thread.is_alive()
            heartbeat_age = now - checker.last_activity if checker.last_activity else None
            healthy = (
                thread_alive
                and checker.connected
                and heartbeat_age is not None
                and heartbeat_age <= 60
            )
            checker_states.append(
                {
                    "account": checker.account,
                    "mailbox": checker.mailbox,
                    "action": checker.action_name,
                    "thread_name": thread.name,
                    "thread_alive": thread_alive,
                    "connected": checker.connected,
                    "heartbeat_age": heartbeat_age,
                    "healthy": healthy,
                }
            )

        state = {
            "pid": os.getpid(),
            "updated_at": now,
            "healthy": bool(checker_states)
            and all(checker["healthy"] for checker in checker_states),
            "checkers": checker_states,
        }
        temporary_file = f"{self.healthfile}.{os.getpid()}.tmp"
        with open(temporary_file, "w", encoding="UTF-8") as health_file:
            json.dump(state, health_file)
        os.replace(temporary_file, self.healthfile)

    def remove_health(self):
        try:
            with open(self.healthfile, "r", encoding="UTF-8") as health_file:
                health = json.load(health_file)
            if health.get("pid") == os.getpid():
                os.unlink(self.healthfile)
        except (OSError, ValueError):
            pass

    def create_checker(
        self,
        account,
        mailbox,
        action,
        sender,
        title_generator=None,
        account_label=None,
    ):
        return Checker(
            self.logger,
            self.stop_event,
            account["server"],
            account["username"],
            account["password"],
            mailbox["mailbox"],
            mailbox["check_for"],
            action,
            sender,
            use_ssl=bool(account["use_ssl"]),
            timeout=int(account["timeout"]),
            remove_flag_after_processing=bool(
                mailbox.get("remove_flag_after_processing", False)
            ),
            archive_after_processing=mailbox.get("archive_after_processing"),
            title_generator=title_generator,
            account=account_label or account.get("account") or "account-1",
        )

    @staticmethod
    def action_uses_openai_title(action):
        return (
            action.get("action") in {"things", "omnifocus"}
            and action.get("title_generator") == "openai"
        )

    @staticmethod
    def account_label(account, index):
        return account.get("account") or f"account-{index + 1}"

    def create_title_generator(self):
        if not any(
            self.action_uses_openai_title(action)
            for action in self.config.get("actions", [])
        ):
            return None

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            log_event(
                self.logger,
                "error",
                "openai_title_disabled",
                reason="missing_api_key",
                fallback="original_subject",
            )
            return None

        config = self.config.get("openai", {})
        model = config.get("model", "gpt-5.6-luna")
        timeout_seconds = config.get("timeout_seconds", 10)
        max_body_chars_per_email = config.get("max_body_chars_per_email", 8000)
        max_batch_chars = config.get("max_batch_chars", 24000)
        try:
            title_generator = OpenAITitleGenerator(
                self.logger,
                api_key,
                model=model,
                timeout_seconds=timeout_seconds,
                max_body_chars_per_email=max_body_chars_per_email,
                max_batch_chars=max_batch_chars,
            )
            log_event(
                self.logger,
                "info",
                "openai_title_enabled",
                model=model,
                timeout_seconds=timeout_seconds,
                max_body_chars_per_email=max_body_chars_per_email,
                max_batch_chars=max_batch_chars,
            )
            return title_generator
        except Exception as exception:
            log_event(
                self.logger,
                "error",
                "openai_title_disabled",
                reason="initialization_failed",
                error_type=type(exception).__name__,
                fallback="original_subject",
            )
            return None

    def start(self):
        self.setup_logging()

        context = LoggingDaemonContext()
        context.loggers_preserve = [self.logger]
        context.stdout_logger = self.stdout_logger
        context.stderr_logger = self.stderr_logger
        context.pidfile = self.pidfile
        context.signal_map = {
            signal.SIGTERM: self.stop,
            signal.SIGINT: self.stop,
        }

        if self.daemon:
            context.detach_process = True
        else:
            context.detach_process = False
            # TODO should this not be below the else statement?
            context.stdout = sys.stdout
            context.stdin = sys.stdin

        # TODO first acquire and then release so we can go back to the command line
        # then do the same in the DaemonContext
        try:
            with context as c:
                accounts = self.config["accounts"]
                mailbox_count = sum(
                    len(account.get("mailboxes", [])) for account in accounts
                )
                log_event(
                    self.logger,
                    "info",
                    "app_started",
                    pid=self.pidfile.read_pid(),
                    account_count=len(accounts),
                    mailbox_count=mailbox_count,
                    daemon=self.daemon,
                )
                sender = Sender(
                    self.logger,
                    self.config["smtp"]["server"],
                    self.config["smtp"].get("username"),
                    self.config["smtp"].get("password"),
                    self.config["smtp"]["from"],
                )
                title_generator = self.create_title_generator()

                for account_index, account in enumerate(accounts):
                    account_label = self.account_label(account, account_index)
                    mailboxes = account["mailboxes"]
                    for mailbox in mailboxes:
                        action = [
                            a
                            for a in self.config["actions"]
                            if a["action"] == mailbox["action"]
                        ][0]
                        checker = self.create_checker(
                            account,
                            mailbox,
                            action,
                            sender,
                            title_generator=(
                                title_generator
                                if self.action_uses_openai_title(action)
                                else None
                            ),
                            account_label=account_label,
                        )
                        checker_thread = CheckerThread(self.logger, checker)
                        self.threads.append(checker_thread)
                        log_event(
                            self.logger,
                            "info",
                            "checker_started",
                            account=checker.account,
                            mailbox=checker.mailbox,
                            action=checker.action_name,
                            server=checker.server_address,
                            check_for=checker.check_for,
                            use_ssl=checker.use_ssl,
                            remove_flag_after_processing=(
                                checker.remove_flag_after_processing
                            ),
                            archive_after_processing=(
                                checker.archive_after_processing
                            ),
                            title_generator=checker.title_generator is not None,
                        )
                        checker_thread.start()

                # we have to do this, otherwise we lose the context and lockfile
                # (after all the threads have been created and detached)
                while not self.stop_event.is_set():
                    dead_threads = [t for t in self.threads if not t.is_alive()]
                    self.write_health()
                    if dead_threads:
                        identities = [
                            f"{thread.checker.account}/{thread.checker.mailbox}"
                            for thread in dead_threads
                        ]
                        log_event(
                            self.logger,
                            "critical",
                            "checker_died",
                            count=len(dead_threads),
                            checkers=identities,
                        )
                        self.stop_event.set()
                        for thread in self.threads:
                            if thread.is_alive():
                                thread.stop()
                        for thread in self.threads:
                            thread.join()
                        # Exiting the main process makes the existing PID-based
                        # Docker healthcheck truthful and lets the restart policy
                        # recover the service.
                        raise RuntimeError(
                            "Checker thread stopped unexpectedly: "
                            + ", ".join(identities)
                        )
                    self.stop_event.wait(1)
        except FileExistsError:
            log_event(self.logger, "debug", "stale_lock_removed")
            self.pidfile.break_lock()
        except AlreadyLocked:
            if not self.force:
                raise SystemExit("Another imapwatch process already running")
            pass
        except LockTimeout:
            raise SystemExit("LockTimeout")
        except NotLocked:
            raise SystemExit("NotLocked")
            pass
        finally:
            self.remove_health()

    def setup_logging(self):
        # configure logging
        logFormatter = logging.Formatter(
            "%(asctime)s %(name)-10.10s [%(process)-5d] [%(levelname)-8.8s] "
            "[%(threadName)s] %(message)s"
        )
        self.logger = logging.getLogger("imapwatch")
        # this shouldn't be necessary? level should be NOTSET standard
        # https://docs.python.org/3/library/logging.html
        self.logger.setLevel(logging.DEBUG)

        # create the filehandler
        self.fileHandler = RotatingFileHandler(
            self.logfile,
            mode="a",
            maxBytes=1048576,
            backupCount=9,
            encoding="UTF-8",
            # if we don't set delay to False, the stream is not opened until we start writing
            # this prevents getLogFileHandler() to find the right handle to preserve
            delay=False,
        )
        self.fileHandler.formatter = logFormatter
        self.logger.addHandler(self.fileHandler)

        # get the (already existing) imapclient logger
        self.imapclient_logger = logging.getLogger("imapclient")
        self.imapclient_logger.addHandler(self.fileHandler)

        self.stdout_logger = logging.getLogger("stdout")
        self.stdout_logger.setLevel(logging.DEBUG)
        self.stdout_logger.addHandler(self.fileHandler)

        self.stderr_logger = logging.getLogger("stderr")
        self.stderr_logger.setLevel(logging.DEBUG)
        self.stderr_logger.addHandler(self.fileHandler)

        consoleHandler = logging.StreamHandler()
        consoleHandler.formatter = logFormatter

        if not self.daemon:
            # Add optional ConsoleHandler
            consoleHandler.setLevel("DEBUG")
            self.logger.setLevel(self.verbose)

            self.logger.addHandler(consoleHandler)
            self.stdout_logger.addHandler(consoleHandler)
            self.stderr_logger.addHandler(consoleHandler)

            # TODO add custom level for imapclient logging on the console
            # or in the configfile?
            self.imapclient_logger.addHandler(consoleHandler)

    def stop(self, signum, frame):
        log_event(
            self.logger,
            "info",
            "app_stopping",
            signal=signum,
            checker_count=len(self.threads),
        )
        self.stop_event.set()
        for t in self.threads:
            t.stop()
            t.join()
        log_event(self.logger, "info", "app_stopped")
