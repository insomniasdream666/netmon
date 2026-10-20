# NetMon usage guide

NetMon is a real-time network monitor and diagnostic assistant for Kali Linux.
Seven asynchronous collectors feed a health-scored model; a deterministic rule
engine handles known faults instantly and a local Ollama model diagnoses
everything else with structured, evidence-backed remediation steps. NetMon
**never executes a fix silently**: every command is shown first and needs an
explicit confirmation.

This guide is the operator reference: commands, the TUI, the web UI, the HTTP
API, configuration, storage, alerts, diagnostics, deployment and
troubleshooting.

- [1. Install and first run](#1-install-and-first-run)
- [2. Command-line reference](#2-command-line-reference)
- [3. Terminal UI (TUI)](#3-terminal-ui-tui)
- [4. Web dashboard and HTTP API](#4-web-dashboard-and-http-api)
- [5. Configuration](#5-configuration)
- [6. Collectors and health scoring](#6-collectors-and-health-scoring)
- [7. Alerting](#7-alerting)
- [8. Diagnostics and fixes](#8-diagnostics-and-fixes)
- [9. Storage and retention](#9-storage-and-retention)
- [10. Deployment](#10-deployment)
- [11. Troubleshooting](#11-troubleshooting)
- [12. Development](#12-development)

---

## 1. Install and first run

### Requirements

| Item | Requirement |
|---|---|
| OS | Kali Linux or another recent Debian-based distribution |
| Python | 3.11 or newer |
| Required tools | `ip`, `ss`, `ping` |
| Optional tools | `nmap` (port scans), `iw`/`iwconfig` (Wi-Fi), `openssl` (TLS certificates), `traceroute`/`tracepath`, `dig`, `journalctl`, `ethtool`, `nmcli` |
| Optional services | InfluxDB 2.x (metric history), Ollama (AI diagnostics) |

```bash
sudo apt update
sudo apt install -y iproute2 iputils-ping procps nmap openssl iw \
  traceroute dnsutils wireless-tools ethtool
```

### Install

From a checkout of the repository:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

On Kali/Debian with an externally managed Python (PEP 668), install into your
user site instead:

```bash
pip install --user --break-system-packages -e ".[dev]"
```

Two helper scripts automate a full setup:

```bash
./scripts/dev-setup.sh --venv        # developer environment + optional InfluxDB
./scripts/install.sh --user          # per-user install + user systemd service
sudo ./scripts/install.sh            # system install in /opt/netmon + system service
sudo ./scripts/install.sh --no-service
```

- `dev-setup.sh` accepts `--venv` (create `./.venv`) and `--no-influx` (skip
  the Docker InfluxDB start).
- `install.sh --user` creates `~/.local/share/netmon/venv`, links
  `~/.local/bin/netmon` and installs a user unit. `install.sh` (system) creates
  `/opt/netmon`, writes a starter configuration and enables a system unit.
  It never overwrites an existing `config.yaml`.

Verify the installation:

```bash
netmon --version
netmon doctor
```

### Files and paths

| Path | Purpose |
|---|---|
| `~/.config/netmon/config.yaml` | Optional YAML configuration. Defaults apply when absent. Created by the installer, `netmon config set` or a settings save in the TUI. |
| `~/.config/netmon/config.db` | SQLite: configuration mirror, diagnostic history, alert rules and alert events. Created automatically. |
| `~/.config/netmon/.env` | Optional `.env` file (see [configuration](#5-configuration)). |
| `~/.config/systemd/user/netmon.service` | User service created by `netmon service install`. |

Overrides:

| Variable | Effect |
|---|---|
| `NETMON_CONFIG_DIR` | Base directory for the default YAML and SQLite paths |
| `NETMON_CONFIG_PATH` | Explicit path to `config.yaml` |
| `NETMON_SQLITE_PATH` | Explicit path to the SQLite database |
| `NETMON_ENV_FILE` | Explicit `.env` file to load |

No configuration file is required to start: every setting has a default.
The SQLite database, tables and default alert rules are created on first use.

### Command cheat sheet

```bash
netmon                              # interactive TUI (default)
netmon --web                        # web dashboard on 0.0.0.0:8080
netmon --web --host 127.0.0.1 --port 9090
netmon --headless                   # daemon, no interface
netmon --no-ai                      # launch with the AI path disabled

netmon status                       # one collection cycle + health summary
netmon status --json                # same, machine-readable
netmon diagnose                     # diagnose the most severe current issue
netmon diagnose gateway_unreachable # diagnose a specific issue
netmon diagnose --no-ai             # rule engine only
netmon scan 192.168.1.10 -p 1-1024  # one-shot nmap scan
netmon doctor                       # verify tools, storage and AI backend

netmon config show                  # effective configuration
netmon config show --json --reveal  # include the InfluxDB token
netmon config get web.port
netmon config set web.port 9090
netmon config validate

netmon service install --scope user # systemd unit
netmon service status --scope user
netmon version
```

---

## 2. Command-line reference

### Global options

Global options belong to the main command and must appear **before** a
subcommand:

```bash
netmon [GLOBAL OPTIONS] [COMMAND] [COMMAND OPTIONS]
```

| Option | Meaning |
|---|---|
| `--web` | Serve the web dashboard instead of the TUI |
| `--headless` | Run the monitor with no interface (systemd/daemon mode) |
| `--host TEXT` | Override `web.host` for this run |
| `--port INT` | Override `web.port` for this run |
| `--config PATH` | Path to `config.yaml` for this run |
| `--log-level LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL` |
| `--no-ai` | Disable the AI diagnosis path for this run |
| `--version` | Print the version and exit |
| `--help` | Show help |

`python -m netmon ...` is equivalent to `netmon ...` when the package is
importable but the console script is not on `PATH`.

### Launch modes

```bash
netmon                       # Textual TUI
netmon --web                 # FastAPI dashboard, 0.0.0.0:8080 by default
netmon --web --host 127.0.0.1 --port 9090
netmon --headless            # logs a summary every 30 seconds
```

- **TUI** (default): the interactive dashboard described in section 3.
- **Web**: one event loop owns the monitor, storage and HTTP server. The
  startup banner prints the dashboard URL; `0.0.0.0` is displayed as
  `localhost`.
- **Headless**: no UI; useful for systemd. It logs
  `health=<score> state=<state> cycles=<n> collectors=<n> alerts=<n>` every
  30 seconds.
- `Ctrl+C` stops any mode gracefully and closes SQLite/InfluxDB clients.

### `netmon status`

Collect once and print the current health summary. The monitor is started,
one cycle runs, then everything is shut down.

```bash
netmon status
netmon status --json
netmon status --config /etc/netmon/config.yaml
```

Text output contains `HOST`, `HEALTH`, `CYCLES`, `INFLUX`, a `COMPONENTS`
table and up to ten `ISSUES`. `--json` emits the complete `SystemState`
document (health, components, issues, snapshot, collectors, scheduler,
diagnostics counters, backend status, alerts).

### `netmon diagnose`

Run a diagnosis once and print the structured result.

```bash
netmon diagnose [ISSUE] [--no-ai] [--config PATH]
```

| Argument/Option | Meaning |
|---|---|
| `ISSUE` | Issue key or issue type. Omit to diagnose the most severe current issue. |
| `--no-ai` | Use only the deterministic rule engine |
| `--config PATH` | Alternative configuration file |

The command first runs a collection cycle, then diagnoses. Output:

```text
DIAGNOSIS   <explanation>
CONFIDENCE  65%  (source: rule)
AI NOTE     <only when the AI path failed>

FIXES
  [0] mtr --report --report-cycles 20 1.1.1.1
      Show per-hop latency and loss to find the slow hop.
  ...

RISKS       ...
VERIFY      ...
```

Fixes are printed for review only; the CLI never executes them. Exit status is
`0` when the command completes, including when there are no active issues or
the issue is critical. It is non-zero only on a fatal error.

### `netmon scan`

One-shot port scan using the configured nmap wrapper.

```bash
netmon scan [TARGET] [-p PORTS] [--config PATH]
```

| Argument/Option | Default | Meaning |
|---|---|---|
| `TARGET` | `127.0.0.1` | Host name, address or CIDR |
| `-p`, `--ports` | `1-1024` | nmap port specification |
| `--config PATH` | default config | Alternative configuration file |

Protocol (`tcp`, `udp`, `both`), service detection and extra arguments come
from `monitoring.port_scan`. SYN scans require root or `CAP_NET_RAW`; without
it nmap falls back to a TCP connect scan. Exit status is `1` when nmap reports
an error.

### `netmon doctor`

Checks the installation and prints four blocks:

| Block | Checks |
|---|---|
| `TOOLS` | Required `ip`, `ss`, `ping`; availability of optional tools |
| `STORAGE` | SQLite open/ping; InfluxDB enabled/configured/reachable |
| `AI` | Ollama reachable and the configured model pulled |
| `SERVICE` | Whether the user unit exists and its state |

Exit status is `1` when a required tool is missing or SQLite cannot be opened.
An unreachable InfluxDB or Ollama is reported but does not fail the command
because both are optional. There is no `--json` flag.

### `netmon config`

```bash
netmon config show [--json] [--reveal] [--config PATH]
netmon config get KEY [--config PATH]
netmon config set KEY VALUE [--config PATH]
netmon config validate [--config PATH]
```

| Command | Behaviour |
|---|---|
| `show` | Print effective `dotted.key = value` pairs. The InfluxDB token is shown as `***` unless `--reveal` is passed. `--json` emits a JSON object. |
| `get` | Print one value, e.g. `netmon config get web.port`. Exit `1` for an unknown key. |
| `set` | Parse and validate the value, then write the **full effective configuration** to `config.yaml` (the InfluxDB token is stripped). Exit `1` on invalid keys or values. |
| `validate` | Validate the configuration file. Exit `1` when the file is invalid. |

`config set` writes YAML, but environment variables still win at runtime.
Use `netmon config show` to see what the process will actually use.

### `netmon service`

```bash
netmon service ACTION [--scope user|system]
```

| Action | Effect |
|---|---|
| `install` | Write the unit, reload systemd and enable/start it |
| `uninstall` | Stop, disable and remove the unit |
| `start` / `stop` / `restart` | Control the service |
| `status` | Print unit, active/sub state, PID and enabled flag |

`--scope user` (default) writes
`~/.config/systemd/user/netmon.service`; `--scope system` writes
`/etc/systemd/system/netmon.service` and needs root. The unit runs
`netmon --headless`. For a user service to start at boot without a login
session:

```bash
sudo loginctl enable-linger "$USER"
```

Logs:

```bash
journalctl --user -u netmon -f     # user scope
journalctl -u netmon -f            # system scope
```

### `netmon version`

```bash
netmon version
netmon --version
```

Both print the version; `--version` also prints the brand tagline.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Command completed successfully |
| `1` | Tool/configuration/operation failure (`doctor`, `scan`, `config`, `service`, fatal runtime error) |
| `2` | Typer usage error (unknown option or command) |

---

## 3. Terminal UI (TUI)

Start with `netmon` (optionally `--no-ai`). The interface uses the
`netmon-dark` theme: `#0D1117` background, `#00D084` healthy, `#FFB800`
warning, `#FF4757` critical, `#00B4D8` informational, JetBrains Mono.

Status glyphs: `●` healthy, `◐` warning, `○` critical or unknown, `⟳`
refreshing.

### Screens

| Screen | Contents |
|---|---|
| **Dashboard** (default) | Overall health card, per-component scores, collector status, metric sparklines, recent alerts, diagnostic feed |
| **Interfaces** | Interface inventory with state, addresses, counters and throughput |
| **Alerts** | Alert history, severity, rule, value and acknowledgement state |
| **Diagnostics** | Current issues, rule/AI diagnosis, proposed fixes and fix results |
| **Settings** | Effective configuration, editable dotted keys and live apply |

### Keys

Global keys:

| Key | Action |
|---|---|
| `q` | Quit NetMon |
| `d` | Open Diagnostics and diagnose the most severe issue |
| `i` | Interfaces screen |
| `a` | Alerts screen |
| `s` | Settings screen |
| `r` | Force an immediate collection cycle |
| `escape` | Back to the dashboard |
| `enter` | Forwarded to the active screen (execute a selected fix) |

Screen-specific keys:

| Screen | Key | Action |
|---|---|---|
| Diagnostics | `d` | Diagnose the selected issue (or the most severe) |
| Diagnostics | `enter` | Diagnose the selected issue, or review the selected fix |
| Fix confirmation | `y` | Execute the command |
| Fix confirmation | `n`, `escape` | Cancel |
| Alerts | `a` | Acknowledge the selected event |
| Alerts | `r` | Reload the event list |
| Settings | `ctrl+s` | Validate and apply the entered key/value |

### Diagnosing and executing a fix

1. Press `d`. The Diagnostics screen opens and automatically diagnoses the
   most severe current issue.
2. Select another issue with the arrow keys and press `enter` (or `d`) to
   diagnose it.
3. Select a fix and press `enter`. A confirmation dialog shows the exact
   command, ownership requirements and danger flags.
4. Press `y` to execute, or `n`/`escape` to cancel.

After execution the command output, exit code and verification result are
shown and stored in diagnostic history. NetMon never runs a fix from the
dashboard or a background task.

### Editing settings

The Settings screen shows every effective key. Enter a dotted key
(`web.port`, `monitoring.intervals.wifi`) and a value, then press `ctrl+s`.
Validated values are applied to the running monitor immediately and written
to `config.yaml`. Environment variables still override them on the next
start.

---

## 4. Web dashboard and HTTP API

Start the server:

```bash
netmon --web                                  # http://localhost:8080
netmon --web --host 127.0.0.1 --port 9090
netmon --web --no-ai                          # rules only
```

The server prints the branded banner and the dashboard URL. All pages are
server-rendered with FastAPI + Jinja2 and enhanced with HTMX; charts use
Chart.js. HTMX 2.0.4 and Chart.js 4.4.7 are vendored under
`netmon/web/static/vendor` and served locally, so the dashboard works without
internet access.

> **Security:** NetMon supports optional HTTP Basic authentication. Set
> `web.auth: true` and `NETMON_WEB_PASSWORD` (plus optional
> `NETMON_WEB_USERNAME`, default `admin`) to protect pages, REST calls,
> WebSocket and SSE streams. `/api/health` is exempt only for loopback clients
> (container health probes) and `/static/` stays public for offline assets.
> Enabling auth without a password is rejected; when set through `/settings`
> the check runs before the value is saved. Basic auth does not encrypt
> traffic, so bind to `127.0.0.1` or use a TLS-terminating reverse proxy on
> untrusted networks.

### Pages

#### Dashboard (`/`)

- Health score, state and component scores.
- Connectivity cards (gateway, internet, latency, packet loss, DNS).
- Interface table with throughput and utilisation.
- Collector status and scheduler information.
- Recent alerts and diagnostic counters.
- Bandwidth and health history charts (InfluxDB, with memory fallback).

The summary, connectivity, interfaces and alerts cards refresh every 5
seconds via HTMX. The page also opens a WebSocket (`/ws/live`) for state
pushes and an SSE stream (`/sse/alerts`) for new alerts.

#### Interfaces (`/interfaces`)

- Table of monitored interfaces with state, addresses, speed, RX/TX rate,
  errors and utilisation.
- `details` expands live counters and a 15-minute bandwidth chart; the panel
  refreshes every 5 seconds.
- Ignored interfaces (matching `monitoring.ignored_interfaces`) are listed
  separately and excluded from health/alerts.

#### Diagnostics (`/diagnostics`)

- Current issues with severity, component, metric and suggested checks.
- `Diagnose` runs the full rule + AI path; `Rule only` skips Ollama.
- The result panel shows source, confidence, diagnosis, proposed fixes,
  risks and the verification command.
- Each fix has a `Run` button. It always asks for browser confirmation and
  shows the exact command; the API additionally requires `confirm: true`.
- **Diagnostic history** lists past diagnoses. Click `view` to load the full
  recorded diagnosis into the result panel, including the outcome of any fix
  that was executed. The entry is also available as a standalone page at
  `/diagnostics/history/{id}`. History auto-refreshes every 15 seconds.

#### Alerts (`/alerts`)

- **Recent alerts** — up to 100 events with severity, rule, value, message,
  delivery status and errors. `acknowledge` marks an event; the table refreshes
  every 15 seconds and immediately after acknowledgements.
- **Threshold rules** — every rule with its condition, severity, cooldown,
  state and last update. `edit` loads the rule into the form; `delete` removes
  it after confirmation. The table refreshes every 30 seconds and immediately
  after a save or delete.
- **Rule editor** — create or replace a rule by name (metric, operator,
  threshold, severity, enabled, cooldown, channel labels, description and
  message template). Changes apply on the next collection cycle.
- **Notification channels** — the channels from `alerts.channels`, with a
  `send test` button per channel. Tests send an `info` probe and are not stored
  as alert events.
- Per-rule `channels` values are stored as labels with the rule; delivery
  currently uses the global `alerts.channels` list. Use the test buttons to
  verify the global channel configuration.

#### Settings (`/settings`)

- Every effective setting grouped by section (`general`, `monitoring`,
  `health`, `alerts`, `ollama`, `storage`, `web`, `tui`).
- Values are rendered by type: toggles for booleans, number inputs, selects for
  enumerated values, and JSON textareas for lists and objects.
- `save` validates the value, applies it live and writes the full effective
  configuration to `config.yaml`. Lists and objects accept JSON such as
  `["8.8.8.8", "1.1.1.1"]`.
- The InfluxDB token is never shown or editable; it remains environment-only.
- `web.auth` applies immediately and requires `NETMON_WEB_PASSWORD`; saving it
  without that environment variable returns a validation error. Use
  `NETMON_WEB_USERNAME` to change the default `admin` username.
- `web.refresh_interval` is labelled **reserved** because the current build
  parses it but the dashboard still uses fixed 5-second HTMX refreshes.
- Environment variables still override saved YAML values on the next start.

### HTML fragments (HTMX)

Pages expose named fragments for partial swaps, for example:

```text
/diagnostics?fragment=issues
/diagnostics?fragment=history
/alerts?fragment=events
/alerts?fragment=rules
/alerts?fragment=channels
/?fragment=summary
/interfaces?interface=eth0&fragment=detail
```

`POST /api/diagnose` and `POST /api/fix` return an HTML fragment instead of
JSON when the request carries `HX-Request: true`. This is what the web UI
uses; API clients should omit the header to receive JSON. Successful write
requests also send `HX-Trigger` response events (`configChanged`,
`rulesChanged`, `alertsChanged`) so the dashboard sections refresh without a
page reload.

### REST API

All endpoints return JSON unless stated otherwise. When `web.auth` is enabled,
send HTTP Basic credentials on every request. `GET /api/health` is exempt only
for loopback clients so container health probes keep working; remote health
requests also require credentials.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Overall score/state, components, issues, collectors, backends |
| GET | `/api/interfaces` | All monitored interfaces with current metrics |
| GET | `/api/interfaces/{name}?range=1h` | One interface, current detail plus history |
| GET | `/api/connectivity` | Gateway, internet, ping, DNS and traceroute results |
| GET | `/api/collectors` | Collector runtime status and scheduler table |
| GET | `/api/metrics/{measurement}` | Time series with Chart.js-ready series |
| POST | `/api/diagnose` | Diagnose an issue (JSON or HTML fragment) |
| POST | `/api/fix` | Execute one recorded fix after confirmation |
| GET | `/api/diagnostics/history?limit=50&issue_type=...` | Recent diagnoses from SQLite |
| GET | `/api/diagnostics/{id}` | One recorded diagnosis |
| GET | `/api/config` | Effective configuration as `dotted.key` values |
| PATCH | `/api/config/{key}` | Validate, persist and apply one setting |
| GET | `/api/alerts?limit=100` | Recent alert events |
| POST | `/api/alerts/{event_id}/acknowledge` | Acknowledge one event |
| POST | `/api/alert-channels/{index}/test` | Send a synthetic alert to one channel |
| GET | `/api/alert-rules` | All threshold rules |
| POST | `/api/alert-rules` | Create or replace a rule (name in the body) |
| PUT | `/api/alert-rules/{name}` | Create or replace a rule by path name |
| DELETE | `/api/alert-rules/{name}` | Delete a rule |
| WS | `/ws/live` | Live `SystemState` JSON pushes |
| SSE | `/sse/alerts` | Alert events as they fire |

#### `GET /api/health`

Returns `score`, `state`, `checked_at`, `components`, `issues`, `collectors`,
`scheduler`, `alerts`, `diagnostics` counters and InfluxDB status. A component
with no data has state `unknown`; when no component is measurable the overall
state is `unknown` rather than a misleading `0.0` score.

#### `GET /api/interfaces` and `/api/interfaces/{name}`

List returns `interfaces`, `count`, `default_route`, `ignored_interfaces` and
`collected_at`. The detail endpoint adds `current`, `history`, `history_count`
and `range`; `range` accepts relative tokens such as `15m`, `1h`, `24h`, `7d`.

#### `GET /api/metrics/{measurement}`

Measurements: `interface_metrics`, `connectivity`, `health_score`,
`port_scan`, `bandwidth`, `connections`, `wifi`, `certificates`.

Query parameters:

| Parameter | Default | Meaning |
|---|---|---|
| `range` | `1h` | Relative window (`15m`, `1h`, `24h`, ...) |
| `interval` | none | Aggregation window (`10s`, `1m`, ...) |
| `field` | all | Repeatable field filter |
| `tag` | none | Repeatable `key:value` tag filter |
| `limit` | `1000` | Maximum raw rows (1-5000) |

```bash
curl 'http://localhost:8080/api/metrics/connectivity?range=1h&interval=10s&field=latency_ms'
curl 'http://localhost:8080/api/metrics/bandwidth?range=15m&tag=interface:eth0'
```

Unknown measurements return `404`; invalid ranges/intervals/tags return `400`.
When InfluxDB is unavailable, `rows` come from the in-memory ring buffer and
the payload reports `available`/`configured` accordingly.

#### `POST /api/diagnose`

```bash
curl -X POST http://localhost:8080/api/diagnose \
  -H 'Content-Type: application/json' \
  -d '{"issue_key": "latency_high", "use_ai": true}'
```

| Field | Meaning |
|---|---|
| `issue_key` | Issue key (or type) to diagnose |
| `issue_type` | Alias accepted when `issue_key` is absent |
| `use_ai` | Default `true`; set `false` to force the rule engine |

Omit the key to diagnose the most severe current issue. Responses:

- `200` with the diagnosis JSON (`id`, `issue`, `issue_type`, `severity`,
  `diagnosis`, `confidence`, `state`, `source`, `fixes`, `risks`, `verify`,
  `created_at`, `duration_ms`, `ai_attempted`, `ai_error`, `rule_name`,
  `model`).
- `404` when no active issue matches, or it disappeared before diagnosis.
- `503` when neither the rule engine nor the AI produced a diagnosis; the
  payload contains `detail` and a fallback `diagnosis`.

With `HX-Request: true`, success and `503` return an HTML diagnosis card
instead of JSON.

#### `POST /api/fix`

```bash
curl -X POST http://localhost:8080/api/fix \
  -H 'Content-Type: application/json' \
  -d '{"diagnosis_id": 42, "fix_index": 0, "confirm": true}'
```

| Field | Meaning |
|---|---|
| `diagnosis_id` | Recorded diagnosis id (from the diagnosis payload) |
| `fix_index` | Index of the fix to execute |
| `confirm` | Must be the literal JSON value `true` |

Responses:

- `200` with `fix_index`, `command`, `executed`, `success`, `exit_code`,
  `output`, `error`, `duration_ms`, `verify_command`, `verify_output`,
  `verify_success`, `blocked_reason`, `history_id`.
- `400` when `confirm` is anything other than JSON `true`.
- `404` for an unknown diagnosis id or fix index.

Commands run through a shell so pipelines such as
`openssl s_client ... | openssl x509` work. Each fix has a 60-second timeout;
verification has a 45-second timeout. The outcome is stored in
`diagnostic_history`.

#### `GET /api/diagnostics/history` and `/api/diagnostics/{id}`

History returns `diagnostics` (newest first), `count`, `limit`, `issue_type`
and aggregate `stats` (`total`, `resolved`, `by_type`). Filter with
`?issue_type=latency_high`; choose a page size with `?limit=1..500`.

#### `GET/PATCH /api/config`

`GET /api/config` returns a flat object such as
`{"web.port": 8080, "ollama.model": "llama3:8b", ...}` with the InfluxDB token
redacted.

```bash
curl -X PATCH http://localhost:8080/api/config/web.port \
  -H 'Content-Type: application/json' \
  -d '{"value": 9090}'
```

The pair is validated, stored in SQLite and `config.yaml`, and applied to the
running monitor. `400` for an invalid value, an unknown section or an attempt
to set `storage.influxdb.token`; `404` for an unknown key within a valid
section. The token is environment-only.

#### Alerts and rules

```bash
curl http://localhost:8080/api/alerts?limit=50
curl -X POST http://localhost:8080/api/alerts/12/acknowledge
curl http://localhost:8080/api/alert-rules
curl -X POST http://localhost:8080/api/alert-channels/0/test
```

`POST /api/alert-rules` takes the full rule including `name` in the body and is
what the web form uses; `PUT /api/alert-rules/{name}` accepts the same fields
without `name` (the path supplies it).

```json
{
  "name": "custom-latency",
  "metric": "connectivity.avg_latency_ms",
  "operator": ">",
  "threshold": 150,
  "severity": "warning",
  "enabled": true,
  "cooldown": 300,
  "channels": ["log"],
  "message_template": "",
  "description": "Latency above 150 ms"
}
```

`operator` is one of `>`, `>=`, `<`, `<=`, `==`, `!=`; `severity` is `info`,
`warning` or `critical`. `channels` accepts a JSON array or a comma-separated
string. The values are stored with the rule as labels; delivery currently uses
the global `alerts.channels` list. `DELETE /api/alert-rules/{name}` removes a
rule.

`POST /api/alert-channels/{index}/test` sends the synthetic message
`NetMon test alert: channel configuration is working.` (`info` severity) to the
channel at that index in `alerts.channels`. It returns `channel`, `type`,
`enabled`, `ok` and `error`. An unknown index is `404`. The test is not stored
as an alert event.

#### Live streams

- `GET /ws/live` — WebSocket. Sends the complete `SystemState` JSON on every
  change and at least every 2 seconds. Closes with code `1013` when no monitor
  is running.
- `GET /sse/alerts` — Server-Sent Events. Emits newly fired alerts as JSON
  `data:` frames and a keepalive every 15 seconds.

---

## 5. Configuration

### Resolution order

Later sources win:

1. Built-in defaults.
2. `config.yaml` (`NETMON_CONFIG_PATH`, default
   `~/.config/netmon/config.yaml`).
3. `.env` values for variables that are **not already set** in the process
   environment.
4. Friendly environment aliases (`OLLAMA_*`, `INFLUX*`, `NETMON_SQLITE_PATH`,
   `NETMON_WEB_*`, `NETMON_ALERTS_ENABLED`, ...).
5. `NETMON_*` variables using `__` as the nested delimiter, e.g.
   `NETMON_WEB__PORT=9090` or
   `NETMON_MONITORING__INTERVALS__WIFI=60`.
6. CLI flags for the current invocation (`--host`, `--port`, `--no-ai`,
   `--config`, `--log-level`).

`.env` search order: `NETMON_ENV_FILE`, then `./.env`, then
`~/.config/netmon/.env`. Only the first file found is loaded. Real environment
variables always beat `.env`.

The SQLite database keeps a copy of the effective configuration for
inspection. It is **not** re-applied on later startups, so editing
`config.yaml` or the environment always takes effect. The InfluxDB token is
never written to SQLite.

Editing routes:

| Method | Scope |
|---|---|
| `netmon config set` | Writes `config.yaml` |
| TUI Settings screen | Applies live, writes `config.yaml` |
| `PATCH /api/config/{key}` | Applies live, writes SQLite and `config.yaml` |
| Environment | Highest precedence, affects the next start |

### `monitoring`

| Key | Default | Notes |
|---|---|---|
| `intervals.interfaces` | `2` | Seconds (1-3600) |
| `intervals.connectivity` | `10` | Ping, DNS, gateway, traceroute |
| `intervals.bandwidth` | `5` | 1-3600 |
| `intervals.ports` | `300` | 10-86400; keep long to avoid scan noise |
| `intervals.connections` | `15` | `ss` connection table |
| `intervals.wifi` | `30` | `iw`/`iwconfig` |
| `intervals.certificates` | `3600` | 60-86400 |
| `targets.ping` | `8.8.8.8`, `1.1.1.1`, `9.9.9.9` | ICMP targets |
| `targets.dns` | `google.com`, `github.com`, `cloudflare.com` | System resolver |
| `targets.traceroute` | `8.8.8.8` | Traceroute targets |
| `targets.certificates` | `github.com:443`, `google.com:443`, `1.1.1.1:443` | TLS endpoints |
| `targets.ports` | `127.0.0.1` | Legacy target list |
| `port_scan.enabled` | `true` | Set `false` to skip nmap |
| `port_scan.targets` | `127.0.0.1` | Scanned targets |
| `port_scan.ports` | `1-1024` | nmap port specification |
| `port_scan.protocol` | `tcp` | `tcp`, `udp` or `both` |
| `port_scan.service_detection` | `true` | nmap `-sV` |
| `port_scan.arguments` | `-sV -T4` | Extra nmap arguments |
| `port_scan.max_targets` | `4` | 1-32 |
| `ignored_interfaces` | `lo`, `docker*`, `veth*`, `br-*`, `virbr*`, `tun*` | Glob patterns; excluded from health and alerts |
| `enabled_collectors` | all seven | Scheduler enable list |
| `history_points` | `120` | In-memory sparkline points per metric (10-5000) |

### `health`

Thresholds:

| Key | Default |
|---|---|
| `thresholds.latency_warning` / `latency_critical` | `50` / `200` ms |
| `thresholds.packet_loss_warning` / `packet_loss_critical` | `1` / `5` percent |
| `thresholds.bandwidth_util_warning` / `bandwidth_util_critical` | `80` / `95` percent |
| `thresholds.dns_latency_warning` / `dns_latency_critical` | `100` / `300` ms |
| `thresholds.dns_failure_warning` / `dns_failure_critical` | `1` / `50` percent |
| `thresholds.wifi_signal_warning` / `wifi_signal_critical` | `-70` / `-80` dBm |
| `thresholds.cert_expiry_warning_days` / `cert_expiry_critical_days` | `30` / `7` days |
| `thresholds.interface_error_warning` / `interface_error_critical` | `1` / `50` |
| `thresholds.health_score_warning` / `health_score_critical` | `80` / `50` |
| `thresholds.connection_count_warning` | `2000` |

Component weights (`health.weights.*`):

| Component | Weight |
|---|---|
| `interfaces` | `1.0` |
| `connectivity` | `1.5` |
| `dns` | `1.5` |
| `bandwidth` | `1.0` |
| `wifi` | `0.75` |
| `certificates` | `1.0` |
| `connections` | `0.5` |

Set a weight to `0` to exclude a component from the overall score.

### `alerts`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Master switch |
| `cooldown` | `300` | Seconds before the same rule/issue can fire again |
| `min_severity` | `warning` | `info`, `warning` or `critical` |
| `max_events` | `500` | SQLite retention for alert events (50-10000) |
| `channels` | `[{type: log}]` | Notification destinations |

A channel:

| Field | Meaning |
|---|---|
| `type` | `log`, `ntfy`, `webhook` or `discord` |
| `url` | Destination URL (topic URL for ntfy, webhook URL for discord) |
| `enabled` | Default `true` |
| `headers` | Extra HTTP headers |

```yaml
alerts:
  cooldown: 120
  min_severity: warning
  channels:
    - type: log
    - type: ntfy
      url: https://ntfy.sh/my-netmon-topic
      enabled: true
    - type: webhook
      url: https://hooks.example.net/netmon
      headers:
        Authorization: Bearer example
    - type: discord
      url: https://discord.com/api/webhooks/...
```

`log` writes through the standard logger. `ntfy` posts the message with
`Title`/`Priority` headers. `webhook` posts the alert record as JSON. `discord`
posts an embed. Delivery failures are recorded per event, never raised into
the monitoring loop.

### `ollama`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Enable the AI diagnosis path |
| `host` | `http://localhost:11434` | Ollama endpoint |
| `model` | `llama3:8b` | Model name |
| `timeout` | `30` | Request timeout in seconds (1-600) |
| `prompt_template` | `default` | `default`, `concise` or `deep` |
| `temperature` | `0.2` | 0.0-2.0 |
| `max_retries` | `1` | Additional attempts after transient failures (0-5) |
| `learning_enabled` | `true` | Feed prior successful fixes into prompts |
| `keep_num_ctx` | `4096` | Ollama context window (minimum 512) |

CPU-only Ollama can take minutes for a single diagnosis. Increase
`timeout` (for example `OLLAMA_TIMEOUT=300`) or use a smaller model.

### `storage`

| Key | Default | Meaning |
|---|---|---|
| `sqlite_path` | `~/.config/netmon/config.db` | SQLite database |
| `influxdb.enabled` | `true` | Enable metric writes/queries |
| `influxdb.url` | `http://localhost:8086` | InfluxDB URL |
| `influxdb.token` | empty | **Environment-only**; required for writes |
| `influxdb.org` | `netmon` | Organisation |
| `influxdb.bucket` | `metrics` | Bucket |
| `influxdb.timeout_ms` | `10000` | Client timeout (500-120000) |
| `retention.diagnostics` | `90` | Days of diagnostic history (1-3650) |
| `retention.metrics` | `30d` | InfluxDB bucket retention, applied at monitor startup when InfluxDB is configured |

Without a token (or with InfluxDB offline) NetMon keeps the last 2000 points
per measurement in memory and serves them through the API. The UI never goes
blank; rows show `source: memory`.

### `web`

| Key | Default | Meaning |
|---|---|---|
| `host` | `0.0.0.0` | Bind address |
| `port` | `8080` | Listen port (1-65535) |
| `auth` | `false` | Require HTTP Basic auth; credentials are environment-only |
| `refresh_interval` | `5` | Reserved; the dashboard uses fixed 5-second HTMX refresh |

### `tui`

| Key | Default | Meaning |
|---|---|---|
| `refresh_interval` | `2.0` | Seconds between dashboard refreshes (0.25-60) |
| `theme` | `netmon-dark` | `netmon-dark`, `textual-dark` or `textual-light` |
| `show_sparklines` | `true` | Show metric trend sparklines |

### Root settings

| Key | Default | Meaning |
|---|---|---|
| `env` | `development` | `development`, `production` or `test` |
| `debug` | `false` | Debug mode |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL` |

### Environment variables

| Variable | Maps to |
|---|---|
| `OLLAMA_HOST` | `ollama.host` |
| `OLLAMA_MODEL` | `ollama.model` |
| `OLLAMA_TIMEOUT` | `ollama.timeout` |
| `INFLUXDB_URL` / `INFLUX_URL` | `storage.influxdb.url` |
| `INFLUXDB_TOKEN` / `INFLUX_TOKEN` | `storage.influxdb.token` |
| `INFLUXDB_ORG` | `storage.influxdb.org` |
| `INFLUXDB_BUCKET` | `storage.influxdb.bucket` |
| `NETMON_SQLITE_PATH` | `storage.sqlite_path` |
| `NETMON_CONFIG_PATH` | YAML file location |
| `NETMON_CONFIG_DIR` | Base directory for default paths |
| `NETMON_ENV_FILE` | Explicit `.env` file |
| `NETMON_WEB_HOST` / `NETMON_WEB_PORT` / `NETMON_WEB_AUTH` | `web.*` |
| `NETMON_WEB_USERNAME` / `NETMON_WEB_PASSWORD` | HTTP Basic credentials (environment-only) |
| `NETMON_ALERTS_ENABLED` | `alerts.enabled` |
| `NETMON_ENV` / `NETMON_DEBUG` / `NETMON_LOG_LEVEL` | Root settings |

Any model path also works with the generic form, e.g.
`NETMON_MONITORING__TARGETS__PING='["1.1.1.1","8.8.8.8"]'`. JSON syntax is
required for lists and objects.

### Example `config.yaml`

```yaml
env: production
log_level: INFO

monitoring:
  intervals:
    interfaces: 2
    connectivity: 10
    bandwidth: 5
    ports: 300
    connections: 15
    wifi: 30
    certificates: 3600
  targets:
    ping: [8.8.8.8, 1.1.1.1, 9.9.9.9]
    dns: [google.com, github.com, cloudflare.com]
    traceroute: [8.8.8.8]
    certificates: ["github.com:443", "google.com:443"]
  port_scan:
    enabled: true
    targets: [127.0.0.1]
    ports: "1-1024"
    protocol: tcp
    service_detection: true
    arguments: "-sV -T4"

health:
  thresholds:
    latency_warning: 50
    latency_critical: 200
    packet_loss_warning: 1
    packet_loss_critical: 5
  weights:
    connectivity: 1.5
    dns: 1.5

alerts:
  enabled: true
  cooldown: 300
  min_severity: warning
  channels:
    - type: log

ollama:
  enabled: true
  host: http://localhost:11434
  model: llama3:8b
  timeout: 30

storage:
  sqlite_path: ~/.config/netmon/config.db
  influxdb:
    enabled: true
    url: http://localhost:8086
    org: netmon
    bucket: metrics
  retention:
    diagnostics: 90
    metrics: 30d

web:
  host: 0.0.0.0
  port: 8080

tui:
  refresh_interval: 2.0
  theme: netmon-dark
  show_sparklines: true
```

---

## 6. Collectors and health scoring

### Collectors

Each collector runs on its own scheduler entry. A failure is isolated: the
error is recorded, other collectors keep running, and the last good data stays
visible.

| Collector | Interval | Source | What it collects |
|---|---|---|---|
| `interfaces` | 2 s | `ip -j addr`, `ip -j link` | Interface state, addresses, MAC/MTU, counters, default route |
| `connectivity` | 10 s | `ping`, resolver, traceroute | Gateway and internet reachability, latency, packet loss, DNS latency/failure rate, traceroute |
| `bandwidth` | 5 s | interface counters | Per-interface RX/TX bytes and packets per second, utilisation |
| `ports` | 300 s | `nmap` | Open ports and service versions for `port_scan.targets` |
| `connections` | 15 s | `ss` | TCP/UDP totals, established/listen/time-wait counts |
| `wifi` | 30 s | `iw`, `iwconfig` | SSID, signal/noise, quality, bitrate, channel, connection state |
| `certificates` | 3600 s | `openssl s_client` | Certificate expiry and validity per configured `host:port` |

Disable a collector by removing it from `monitoring.enabled_collectors` (or
disable all port scanning with `monitoring.port_scan.enabled: false`). Tools
are invoked with argument vectors and hard timeouts; only user-confirmed fixes
use a shell.

### Health components

| Component | Weight | Evaluates |
|---|---|---|
| `interfaces` | 1.0 | Down interfaces, error/drop counters |
| `connectivity` | 1.5 | Gateway, internet latency/loss, traceroute |
| `dns` | 1.5 | Lookup failures and latency |
| `bandwidth` | 1.0 | Highest interface utilisation |
| `wifi` | 0.75 | Connection state and signal strength |
| `certificates` | 1.0 | Days until expiry |
| `connections` | 0.5 | Connection count overload |

The overall score is the weighted mean of all components with data. Components
with no data are excluded. When **no** component can be measured, the state is
`unknown` and the score is not treated as a critical failure; alert rules that
use `health.score` are skipped until data exists.

States come from the health thresholds:

- `ok`: score at or above `health_score_warning` (80 by default).
- `warning`: between `health_score_critical` and `health_score_warning`.
- `critical`: below `health_score_critical` (50 by default).
- `unknown`: nothing measurable.

Each component also emits issues with a severity (`info`, `warning`,
`critical`), a component, a metric and a human-readable message. Issues feed
alerts and diagnostics.

---

## 7. Alerting

Two paths run after every collection cycle:

1. **Issue-derived** — `warning` and `critical` health issues fire alerts
   (deduplicated by issue key and cooldown).
2. **Threshold rules** — rules stored in SQLite are evaluated against a flat
   metric map (`build_metric_map`). Metrics include
   `health.score`, `connectivity.avg_latency_ms`,
   `connectivity.avg_packet_loss`, `connectivity.gateway.success`,
   `dns.failure_rate`, `dns.avg_latency_ms`,
   `bandwidth.<iface>.utilization_percent`, `interface.<iface>.is_up`,
   `wifi.<iface>.signal_dbm`, `certificates.<target>.days_remaining`,
   `connections.total` and the component metrics.

### Default rules

| Name | Metric | Condition | Severity |
|---|---|---|---|
| `gateway-unreachable` | `connectivity.gateway.success` | `== 0` | critical |
| `high-latency` | `connectivity.avg_latency_ms` | `> 200` | warning |
| `packet-loss` | `connectivity.avg_packet_loss` | `> 5` | critical |
| `dns-failures` | `dns.failure_rate` | `> 50` | critical |
| `bandwidth-saturated` | `bandwidth.peak_utilization` | `> 95` | warning |
| `certificate-expiring` | `certificates.soonest_expiry_days` | `< 7` | critical |
| `health-score-low` | `health.score` | `< 50` | critical |

Default rules are seeded on first start. A rule can be replaced or removed via
the HTTP API; changes take effect on the next cycle without a restart.

### Cooldown, severity and retention

- `alerts.cooldown` prevents the same rule or issue from firing repeatedly.
- `alerts.min_severity` suppresses lower-severity notifications.
- `alerts.max_events` caps retained alert events; pruning runs every 15
  minutes.
- Events are persisted in `alert_events`, acknowledgeable from the TUI (`a`)
  and the API, and streamed to the web UI over SSE.

---

## 8. Diagnostics and fixes

`netmon diagnose`, the TUI `d` key, the web `Diagnose` button and
`POST /api/diagnose` all use the same engine.

### Flow

1. **Context** — a 15-minute metric window, network configuration, recent
   journal entries and similar past diagnoses.
2. **Rules first** — 17 deterministic rules cover common faults. A match with
   confidence at or above 70 skips the AI call and answers immediately.
3. **AI fallback** — the local Ollama model receives the strict JSON contract
   `diagnosis`, `confidence`, `fixes`, `risks`, `verify`. A timeout, malformed
   JSON, missing model or unreachable server falls back to the rule verdict.
   The AI result is used when its confidence is at least the rule's.
4. **Record and learn** — the diagnosis is stored in SQLite. With
   `ollama.learning_enabled`, successful past fixes for the same issue type
   are included in future prompts.

### Rule coverage

| Rule | Detects |
|---|---|
| `gateway-unreachable` | Default gateway silent to ARP/ICMP |
| `internet-unreachable` | External probes fail while the local link is up |
| `dns-resolution-failure` | Name resolution failures |
| `high-latency` | RTT above threshold without hard failure |
| `packet-loss` | Loss above threshold |
| `wifi-weak-signal` | Signal at or below the configured dBm threshold |
| `wifi-disconnected` | Wi-Fi interface not associated |
| `interface-down` | A monitored interface is down |
| `interface-errors` | Rising RX/TX error or drop counters |
| `bandwidth-saturated` | Interface near link saturation |
| `certificate-expiring` | Certificate expires soon |
| `certificate-expired` | Certificate already expired |
| `firewall-blocking` | Firewall rules drop traffic |
| `connection-overload` | Excessive connection count |
| `port-closed` | Expected service port closed |
| `vpn-tunnel` | VPN/tunnel interface state |
| `dhcp-no-lease` | No lease/address on the uplink |

### Output

Every diagnosis contains the issue, severity, explanation, confidence,
source (`rule`, `ai` or `fallback`), proposed fixes (command, explanation,
root requirement, danger flag), risks and a verification command. The web UI
and CLI show exactly the same fields; the TUI and web history store the same
record.

### Fix safety

- Nothing executes automatically. The CLI only prints commands.
- The TUI requires `y` in a confirmation dialog. The web UI uses a browser
  confirmation plus the API's literal `confirm: true` requirement.
- Commands are classified against destructive patterns (for example
  `rm -rf /`, `mkfs`, `dd if=`) and labelled `dangerous` in every interface.
- `requires_root` is shown before execution. NetMon does not silently use
  `sudo`; the command is displayed exactly as proposed.
- Fix commands run through a shell so pipelines work, with a 60-second hard
  timeout. Verification runs afterwards with a 45-second timeout. Output,
  exit code and verification result are stored in diagnostic history.
- A fix is marked `resolved` when it exits successfully and verification does
  not fail; otherwise the outcome is `attempted` or `failed`.

### AI setup

```bash
ollama serve
ollama pull llama3:8b
netmon doctor
```

If diagnoses report `AI path: attempted, failed (...)`, check `OLLAMA_HOST`,
the model name and the timeout. CPU generation is slow; `OLLAMA_TIMEOUT=300`
is reasonable for `llama3:8b` on a laptop. Rule-only operation is always
available with `--no-ai` or `ollama.enabled: false`.

---

## 9. Storage and retention

### SQLite

`config.db` contains four tables:

| Table | Contents |
|---|---|
| `config` | Effective settings mirror (InfluxDB token excluded) |
| `diagnostic_history` | Every diagnosis, proposed fixes, executed command, output, verification, resolution and learning note |
| `alert_rules` | Default and custom threshold rules |
| `alert_events` | Fired alerts, severity, metric, value and acknowledgement |

Maintenance runs every 15 minutes: alert events are trimmed to
`alerts.max_events`, and diagnoses older than `storage.retention.diagnostics`
days are deleted. SQLite uses short-lived sessions per operation, so the TUI,
web requests and the scheduler can safely share it.

### InfluxDB

Measurements written by the monitor:

| Measurement | Tags | Fields |
|---|---|---|
| `interface_metrics` | `interface`, `hostname` | `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `rx_errors`, `tx_errors`, `rx_dropped`, `tx_dropped`, `mtu`, `is_up` |
| `connectivity` | `target`, `type` (`ping`/`dns`/`gateway`/`internet`) | `latency_ms`, `packet_loss`, `success` |
| `bandwidth` | `interface` | `rx_bytes_per_sec`, `tx_bytes_per_sec`, `rx_packets_per_sec`, `tx_packets_per_sec`, `utilization_percent` |
| `port_scan` | `target`, `protocol` | `open_ports`, `scan_duration_ms` |
| `connections` | none | `total`, `tcp`, `udp`, `established`, `listen`, `time_wait` |
| `wifi` | `interface`, `ssid` | `signal_dbm`, `noise_dbm`, `quality_percent`, `bitrate_mbps`, `channel`, `connected` |
| `certificates` | `target` | `days_remaining`, `expired` |
| `health_score` | `component` (`overall` plus each component) | `score` |

Booleans are written as `1`/`0`; timestamps are UTC. Example Flux query:

```flux
from(bucket: "metrics")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "connectivity" and r._field == "latency_ms")
```

InfluxDB bucket retention is a bucket property. NetMon applies
`storage.retention.metrics` (default `30d`) to the configured bucket at
startup when InfluxDB is configured and the token has permission to update
buckets. The bundled compose file also creates the bucket with 30-day
retention (`DOCKER_INFLUXDB_INIT_RETENTION=30d`). A token without bucket-update
permission logs a warning and monitoring continues; retention is then whatever
the bucket already has.

When InfluxDB is unavailable, the last 2000 points per measurement are kept in
memory and used by `/api/metrics/*` and the interface history. The API response
marks the source, so stale or fallback data is distinguishable.

---

## 10. Deployment

### systemd

```bash
netmon service install --scope user
netmon service start --scope user
netmon service status --scope user
journalctl --user -u netmon -f
```

For a system-wide service (run as root):

```bash
sudo netmon service install --scope system
sudo systemctl status netmon
```

The generated unit runs `netmon --headless` with the project working directory.
It sets `NETMON_CONFIG_PATH=~/.config/netmon/config.yaml`; use
`systemctl edit netmon` (or the installer unit in `scripts/netmon.service`) to
add `Environment=INFLUXDB_TOKEN=...`, an `EnvironmentFile`, or other settings.
Secrets belong in environment files, not in the YAML.

### Docker Compose

The stack in `docker/docker-compose.yml` runs NetMon and InfluxDB:

```bash
export INFLUX_TOKEN="$(openssl rand -hex 24)"
export INFLUXDB_PASSWORD="$(openssl rand -hex 16)"
export NETMON_WEB_PASSWORD="$(openssl rand -hex 16)"
echo "NetMon login: ${NETMON_WEB_USERNAME:-admin} / $NETMON_WEB_PASSWORD"
docker compose -f docker/docker-compose.yml up -d
# dashboard: http://localhost:8080 (HTTP Basic auth)
```

| Service | Purpose |
|---|---|
| `influxdb` | InfluxDB 2.7, bucket `metrics`, 30-day retention |
| `netmon` | Web dashboard on port 8080, SQLite volume, InfluxDB wired |
| `netmon-host` | Optional profile `host-net`: host network stack for real interface visibility and scans |

Key environment variables for the containers:

| Variable | Required | Meaning |
|---|---|---|
| `INFLUX_TOKEN` | yes | InfluxDB admin token, also used by NetMon |
| `INFLUXDB_PASSWORD` | yes | Initial InfluxDB admin password |
| `NETMON_WEB_PASSWORD` | yes | Dashboard HTTP Basic auth password |
| `NETMON_WEB_USERNAME` | no | Dashboard username, defaults `admin` |
| `INFLUXDB_ORG` / `INFLUXDB_BUCKET` | no | Defaults `netmon` / `metrics` |
| `OLLAMA_HOST` | no | Defaults to `http://host.docker.internal:11434` |
| `OLLAMA_MODEL` | no | Defaults to `llama3:8b` |
| `NETMON_ALERTS_ENABLED` | no | Defaults `true` |

The default bridge network only exposes the container's own interfaces; use
the `host-net` profile when monitoring the host network stack:

```bash
docker compose -f docker/docker-compose.yml --profile host-net up -d netmon-host
```

Ollama is expected on the host. If it runs elsewhere, set `OLLAMA_HOST` to a
reachable URL. Compose enables `web.auth`, so the dashboard requires the
password above. The NetMon container healthcheck calls `/api/health` over
loopback, which stays exempt; remote health calls require credentials. Put
these exports in a protected environment file rather than committing them.

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `netmon: command not found` | The console script is not on `PATH`. Use `~/.local/bin/netmon`, `python -m netmon`, or install with `scripts/install.sh --user`. |
| `doctor` reports missing `ip`, `ss` or `ping` | Install `iproute2` and `iputils-ping`; these are required. Optional tools can stay missing. |
| InfluxDB unavailable / no history | Set `INFLUXDB_TOKEN` or `INFLUX_TOKEN` (environment only), check the URL/org/bucket and `docker compose ps`. Monitoring continues with the in-memory fallback. |
| AI diagnosis says the AI path failed | Start Ollama (`ollama serve`), pull the configured model (`ollama pull llama3:8b`), check `OLLAMA_HOST`, and raise `OLLAMA_TIMEOUT` for CPU-only hosts. Rule-based diagnosis still works. |
| Diagnosis button in the web UI returns an error toast | Update to the current version; the UI JSON-encodes HTMX payloads. If you use a reverse proxy, allow `POST` to `/api/diagnose` and `/api/fix`. |
| Web UI renders but charts/actions do nothing | Confirm `/static/vendor/htmx.min.js` and `/static/vendor/chart.umd.min.js` return `200`; a reverse proxy may be blocking `/static/`. |
| Web UI is reachable from other hosts | Bind `--host 127.0.0.1`, enable `web.auth` with `NETMON_WEB_PASSWORD`, and/or add a TLS-terminating reverse proxy. |
| Enabling `web.auth` fails validation | Export a non-empty `NETMON_WEB_PASSWORD` in the environment (and the same variable for the service/container), then retry. |
| Browser keeps asking for the dashboard password | Confirm `NETMON_WEB_USERNAME`/`NETMON_WEB_PASSWORD` match the running process; environment changes need a restart. |
| Change in `config.yaml` has no effect | An environment variable with the same setting wins. Run `netmon config show` and compare. `.env` values also compete; real environment variables win. |
| A fix did not run | The API requires literal `confirm: true`; the TUI asks `y`; commands are never executed from the CLI. A blocked result includes `blocked_reason`. |
| Port scans are slow or noisy | Increase `monitoring.intervals.ports`, shrink `port_scan.ports`, or set `port_scan.enabled: false`. |
| SYN scan denied | nmap needs root or `CAP_NET_RAW`; otherwise it falls back to a TCP connect scan. |
| Wi-Fi fields `noise_dbm`, `security` or `standard` are null | The installed `iw` does not expose them; `iwconfig` is used as a fallback where available. |
| Journal section in AI prompts is empty | Add your user to the `systemd-journal` group and log in again: `sudo usermod -aG systemd-journal "$USER"`. |
| Health is warning/critical on a healthy desktop | Ignored-interface patterns may not match a bridge/VPN device, or public DNS latency is genuinely high. Check the component issues and adjust `monitoring.ignored_interfaces` or thresholds. |
| Empty snapshot shows `unknown` | Expected: no measurable component means no meaningful score. Alert rules using `health.score` are skipped until data arrives. |
| Diagnostics history cannot be opened | Click `view` in the history table. If the page is from an older build, restart the server and refresh; the current build links each row to `/diagnostics/history/{id}`. |
| Web port already in use | Choose another port with `--port` or `netmon config set web.port 9090`. |
| Permission denied writing configuration | The config directory or YAML is read-only. NetMon applies changes live but reports that the file could not be saved. Fix ownership/mode (`chmod 600 ~/.config/netmon/config.yaml`). |

---

## 12. Development

```bash
python -m pytest -q                    # full suite
python -m pytest tests/unit -q         # fast unit tests
python -m pytest tests/integration -q  # end-to-end pipeline
ruff check .                           # lint
mypy netmon/                           # type check
```

The collector data contract is documented in
[COLLECTOR_CONTRACT.md](COLLECTOR_CONTRACT.md). The original product
specification is in the parent `netmon/docs/` directory.

Useful development commands:

```bash
./scripts/dev-setup.sh --venv
netmon doctor
netmon status --json | python3 -m json.tool
netmon --web --host 127.0.0.1 --port 8080 --log-level DEBUG
```
