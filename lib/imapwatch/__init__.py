__all__ = ["checker", "sender", "filelikelogger", "loggingdaemoncontext"]

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
from .loggingdaemoncontext import LoggingDaemonContext


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
                    "mailbox": thread.name,
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

    def create_checker(self, account, mailbox, action, sender):
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
        )

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
                self.logger.info("---------------")
                self.logger.info(f"Starting daemon with pid {self.pidfile.read_pid()}")
                sender = Sender(
                    self.logger,
                    self.config["smtp"]["server"],
                    self.config["smtp"].get("username"),
                    self.config["smtp"].get("password"),
                    self.config["smtp"]["from"],
                )

                self.logger.info("Setting up mailboxes")
                for account in self.config["accounts"]:
                    mailboxes = account["mailboxes"]
                    for mailbox in mailboxes:
                        action = [
                            a
                            for a in self.config["actions"]
                            if a["action"] == mailbox["action"]
                        ][0]
                        checker = self.create_checker(
                            account, mailbox, action, sender
                        )
                        checker_thread = CheckerThread(self.logger, checker)
                        self.threads.append(checker_thread)
                        checker_thread.start()

                # we have to do this, otherwise we lose the context and lockfile
                # (after all the threads have been created and detached)
                while not self.stop_event.is_set():
                    dead_threads = [t.name for t in self.threads if not t.is_alive()]
                    self.write_health()
                    if dead_threads:
                        names = ", ".join(dead_threads)
                        self.logger.critical(
                            f"Checker thread stopped unexpectedly: {names}"
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
                            f"Checker thread stopped unexpectedly: {names}"
                        )
                    self.stop_event.wait(1)
        except FileExistsError:
            self.logger.debug("Removed stale lock file")
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
            "%(asctime)s %(name)-10.10s [%(process)-5d] [%(levelname)-8.8s] [%(threadName)-11.11s] %(message)s"
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
        self.logger.debug("Stopping")
        self.stop_event.set()
        # TODO should we use threading.enumerate() to stop threads?
        # https://docs.python.org/3/library/threading.html
        for t in self.threads:
            # self.logger.debug(f'Calling stop() for thread {t.name}')
            t.stop()
            # self.logger.debug(f'Finished stop() for thread {t.name}')
            # self.logger.debug(f'Calling join() for thread {t.name}')
            t.join()
            # self.logger.debug(f'Finshed join() for thread {t.name}')
        self.logger.info("Stopped")
