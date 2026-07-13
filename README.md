# imapwatch

Daemon (as robust as possible) that can watch for changes (e.g. new or flagged mesages) in IMAP folders using the IDLE command ([RFC 2177](https://tools.ietf.org/html/rfc2177)). Possible to execute a command upon changes, e.g. sending a specific message to your todo-list e-mail address (or basically anything you can build in Python). I'm using it to watch for flagged e-mails and automatically create an item in my Things 3 inbox.

## Usage

```
mdbraber@spiff:~/imapwatch/$ ./imapwatch.py -h
usage: imapwatch [-h] [-b BASEDIR] [-c CONFIGFILE] [-d] [-f] [-l LOGFILE]
                 [-p PIDFILE] [-v {CRITICAL,ERROR,WARNING,INFO,DEBUG}]
                 {start,stop,restart} ...

positional arguments:
  {start,stop,restart}  Actions for imapwatch - default: "start"
    start               Starts imapwatch
    stop                Stops imapwatch
    restart             Restarts imapwatch

optional arguments:
  -h, --help            show this help message and exit
  -b BASEDIR, --base-dir BASEDIR
                        Path to basedir - default: ''
  -c CONFIGFILE, --configfile CONFIGFILE
                        Path to logfile - default: imapwatch.yml
  -d, --daemon          Run as daemon
  -f, --force           Force action (start or stop)
  -l LOGFILE, --logfile LOGFILE
                        Path to logfile - default: log/imapwatch.log
  -p PIDFILE, --pidfile PIDFILE
                        Path to PID file, needs full path! - default:
                        /tmp/imapwatch.pid
  -v {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --loglevel {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Loglevel for the console logger - default: INFO
```

## Configuration (example)

Example configuration in [YAML syntax](http://pyyaml.org/wiki/PyYAMLDocumentation) (also included as `imapwatch_example.yml`). Actions are examples and you could/should build your own (`things` is included as an example and exists in the current code). Check [imapwatch/checker.py](blob/master/imapwatch/checker.py) for the relevant code (see the `dispatch` function). 

You can (for now) use multiple accounts, multiple actions and a single SMTP server. Take good care
of writing good YAML syntax (check for when to use `-` as delineator for blocks) and use `['']` with
the `check_for` item.

To use this configuration file, rename to `imapwatch.yml` (or specify a different file using the
`-c` / `--configfile` parameter).

```
accounts:
  - account: 'provider'
    server: 'imap.provider.com'
    username: 'john@provider.com'
    password: 'mysecretpass'
    use_ssl: True
    timeout: 15
    mailboxes:
      - mailbox: 'INBOX'
        check_for: ['flagged']
        action: 'things'
        remove_flag_after_processing: true
        archive_after_processing: 'Archive'
      - mailbox: '+Later'
        check_for: ['flagged']
        action: 'things'
      - mailbox: '+News'
        check_for: ['flagged']
        action: 'things'
      - mailbox: '+TODO'
        check_for: ['new']
        action: 'things'

actions:
  - action: 'things'
    email: 'add-to-things-xxxxxxx@things.email'
    title_generator: 'openai'

openai:
  model: 'gpt-5.6-luna'
  timeout_seconds: 10
  max_body_chars_per_email: 8000
  max_batch_chars: 24000

smtp:
  server: 'smtp.provider.com'
  username: 'john@provider.com'
  password: 'mysecretpass'
  from: 'john@provider.com'
```

### AI-generated task titles

Things and OmniFocus actions can opt in to action-oriented task titles generated from the sender,
subject, and readable body text of all emails in a dispatch. Add `title_generator: 'openai'` to an
action and provide the API key through the environment:

```sh
export OPENAI_API_KEY='your-api-key'
docker compose up -d
```

The optional top-level `openai` settings shown above default to model `gpt-5.6-luna`, a 10-second
timeout, 8,000 body characters per email, and 24,000 body characters across the batch. The batch
budget is divided evenly so every email contributes context. Inline plain text is preferred;
HTML-only messages are converted to readable text, and attachments are excluded. The request is
made with response storage disabled. Titles target 4–10 words, front-load specific names and
topics, and never include emojis or decorative prefixes.

Only opted-in Things and OmniFocus actions fetch message bodies or call OpenAI. If the API key is
missing, the request fails, or the response is not a valid single-line title of at most 120
characters, imapwatch logs the failure without email content and creates the task with the original
first email subject. The existing combined task notes and message links are unchanged.

At startup, imapwatch logs the active OpenAI model, timeout, and context limits. Each generation
logs its start at debug level. Successful generations log the account, mailbox, action, model,
email count, latency, response ID, and input/output token counts at info level; the generated title
is logged only at debug level. Failures log operational metadata and the exception type without
email content.

### Logging

Application events use searchable `event=... key=value` messages. Mailbox events include the
configured `account`, `mailbox`, and `action`, for example:

```text
event=mailbox_connected account=provider mailbox=INBOX action=things duration_ms=184
event=messages_detected account=provider mailbox=INBOX action=things count=1 sequence_numbers=[1]
event=smtp_send_succeeded account=provider mailbox=INBOX action=things count=1 duration_ms=391
```

If an account has no `account` label, imapwatch assigns `account-1`, `account-2`, and so on in
configuration order. INFO logs contain operational state, counts, identifiers, timing, and
outcomes. Sender names, email subjects, generated titles, and delivery addresses are restricted to
DEBUG. Email bodies, SMTP message contents, passwords, and API keys are never logged. Recoverable
IMAP disconnects use WARNING while unexpected checker termination remains CRITICAL.

`smtp.username` and `smtp.password` are optional for SMTP relays that do not require
authentication. Omit both fields to send without calling SMTP `LOGIN`:

```yaml
smtp:
  server: 'hades.cerberus.group'
  from: 'imapwatch@cerberus.group'
```

SMTP connections continue to use port 587 with STARTTLS. If authentication is needed, both
`username` and `password` must be provided.

Each watched mailbox can optionally change a message after its configured action has been sent
successfully:

- `remove_flag_after_processing: true` removes the standard IMAP `\Flagged` flag.
- `archive_after_processing: 'Archive'` moves the message to the named folder. The folder must
  already exist. imapwatch uses `MOVE` when available; otherwise it safely falls back to
  `COPY`, `\Deleted`, and UID-scoped expunge when the authenticated session supports `UIDPLUS`.
  This enables the fallback for iCloud only when iCloud advertises `UIDPLUS` after login.

Both options are disabled when omitted and can be enabled independently. If both are enabled,
imapwatch removes the flag before archiving the message. SMTP delivery remains asynchronous; failed
SMTP delivery leaves the original message untouched. Post-processing failures are logged and are
not retried automatically. If a server supports neither `MOVE` nor `UIDPLUS`, archiving is skipped
without changing the original message. imapwatch never uses mailbox-wide `EXPUNGE`.

## Want to help?

Feel free to file an issue or create a pull request!
