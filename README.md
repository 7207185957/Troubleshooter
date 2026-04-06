# EC2 Troubleshooter

A **generic, read-only EC2 diagnostic agent** that reacts to anomaly alerts,
investigates affected EC2 instances, and delivers structured findings to a
reporting layer such as Google Chat, a ticketing system, or an incident UI.

The agent **never performs remediation** – it only observes, collects
evidence, and reports.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Anomaly platform  (GChat alert, CloudWatch Alarm, Datadog webhook, …)   │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ HTTP POST /alert
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Alert Receiver  (FastAPI)                                               │
│   • Normalises payload into canonical Alert model                        │
│   • Dispatches investigation as background task                          │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Investigation Orchestrator                                              │
│   • Iterates over all instance_ids in the alert                          │
│   • Resolves private IP via EC2 describe, passes it to Prometheus tools  │
│   • Queries alert contributor metrics from Mimir by name                 │
│   • Passes raw results through EvidenceAnalyzer                          │
│   • Assembles InvestigationReport                                        │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  EC2 Tool Server  (MCP-style bounded interface)                          │
│                                                                          │
│  ┌─────────────────────┐  ┌────────────────────────┐  ┌───────────────┐ │
│  │  EC2 Tools          │  │  Prometheus Tools       │  │  SSM Tools    │ │
│  │  describe_instance  │  │  node_metrics           │  │  Allowlist    │ │
│  │  get_instance_status│  │  query (raw PromQL)     │  │  (20+ cmds)   │ │
│  │  describe_volumes   │  │  query_range            │  │  read-only    │ │
│  │  get_console_output │  │  contributor_metric     │  │  shell cmds   │ │
│  └──────────┬──────────┘  └──────────┬─────────────┘  └───────┬───────┘ │
│             │  AWS EC2 API           │  PromQL HTTP API        │ SSM     │
└─────────────┼────────────────────────┼─────────────────────────┼─────────┘
              │                        │                         │
              │  VPC endpoints         │  Internal Mimir URL     │
              ▼                        ▼                         ▼
         AWS EC2 API          Grafana Mimir / Prometheus   AWS SSM Run Command
                              (X-Scope-OrgID per tenant)
```

### Key design decisions

| Decision | Rationale |
|---|---|
| **MCP-style tool server boundary** | The orchestrator never talks to AWS or Mimir directly. All calls go through `EC2ToolServer`, which enforces the read-only and allowlist contracts. |
| **Prometheus/Mimir for metrics** | All node-level and app-specific metrics come from Grafana Mimir via the Prometheus-compatible HTTP API (`/api/v1/query`, `/api/v1/query_range`). No CloudWatch. `X-Scope-OrgID` is sent on every request for multi-tenant Mimir. |
| **Instance IP → Prometheus label** | The orchestrator resolves the private IP via EC2 `describe_instances`, then uses it as a `instance=~"<ip>(:[0-9]+)?"` label selector so node_exporter series are correctly matched regardless of port. |
| **Contributor metric passthrough** | Alert contributor `metric_name` values that look like valid PromQL metric names are automatically queried against Mimir so the exact signal that fired the alert appears in the report. |
| **SSM allowlist** | Only 20 pre-approved, audited read-only shell commands can run via SSM. No freeform shell. No arbitrary command construction. |
| **No SSH** | All host-level commands go through AWS SSM Run Command (requires SSM agent + IAM role). No ports to open, no keys to manage. |
| **VPC endpoint support** | Every boto3 client accepts an `endpoint_url` override (EC2, SSM, STS). Mimir is an internal URL by nature and needs no special routing. |
| **Generic diagnostics only** | No app-specific logic. The tool layer only answers OS/infrastructure questions. App-specific metric interpretation is left to the human responder. |
| **No remediation** | The agent never restarts services, reboots instances, modifies ASGs or changes configurations. |

---

## Quick start

### Prerequisites

- Python 3.11+
- AWS credentials with the [required IAM permissions](#iam-permissions)
- (Optional) VPC Interface Endpoints for air-gapped deployments

### Install

```bash
pip install -e .
```

### Configure

```bash
cp .env.example .env
# Edit .env with your AWS region, reporter settings, etc.
```

### Run

```bash
# As a Python module (reads .env automatically)
python -m ec2_troubleshooter

# Or with explicit env vars
AWS_REGION=us-east-1 REPORTER_TYPE=log python -m ec2_troubleshooter
```

The agent starts a FastAPI server on `0.0.0.0:8080` by default.

---

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/health` | Liveness check |
| `GET`  | `/tools` | List all allowlisted diagnostic tools |
| `POST` | `/alert?source=generic` | Accept alert (async, HTTP 202) |
| `POST` | `/alert/sync?source=generic` | Accept alert (sync, returns full report) |

### Alert payload format

The receiver accepts three source formats controlled by the `source` query
parameter:

**`generic` (default) – canonical format**

```json
{
  "alert_id": "alert-001",
  "source": "my-anomaly-platform",
  "title": "High CPU on kafka-broker fleet",
  "severity": "HIGH",
  "instance_ids": ["i-0abc123def456789a", "i-0abc123def456789b"],
  "archetype": "kafka-broker",
  "contributors": [
    {
      "metric_name": "CPUUtilization",
      "value": 94.5,
      "threshold": 80.0,
      "unit": "Percent"
    }
  ]
}
```

**`cloudwatch_alarm` – EventBridge / SNS CloudWatch alarm state change**

Pass the raw EventBridge event detail object. Instance IDs are extracted from
alarm dimensions automatically.

**`datadog` – Datadog monitor webhook**

Instance IDs are extracted from `tags` as `instance_id:i-xxx`. Archetype is
extracted from `archetype:value` tags.

---

## Configuration reference

All settings are environment variables (or `.env` file entries).

| Variable | Default | Description |
|---|---|---|
| `AWS_REGION` | `us-east-1` | AWS region |
| `AWS_PROFILE` | _(none)_ | Named AWS profile |
| **Air-gapped VPC endpoints** | | |
| `USE_VPC_ENDPOINTS` | `false` | Route all AWS SDK calls through VPC endpoints |
| `VPC_ENDPOINT_EC2` | _(none)_ | EC2 VPC interface endpoint URL |
| `VPC_ENDPOINT_SSM` | _(none)_ | SSM VPC interface endpoint URL |
| `VPC_ENDPOINT_STS` | _(none)_ | STS VPC interface endpoint URL |
| **Prometheus / Grafana Mimir** | | |
| `PROMETHEUS_URL` | _(none)_ | Mimir query frontend base URL, e.g. `http://mimir.internal:8080/prometheus` |
| `PROMETHEUS_ORG_ID` | _(none)_ | Mimir tenant ID — sent as `X-Scope-OrgID` header |
| `PROMETHEUS_INSTANCE_LABEL` | `instance` | Label that identifies the host, e.g. `instance` for node_exporter |
| `PROMETHEUS_LOOKBACK_MINUTES` | `60` | How many minutes of history to query |
| `PROMETHEUS_STEP_SECONDS` | `60` | Range query resolution in seconds |
| `PROMETHEUS_TOKEN` | _(none)_ | Bearer token (Grafana service account) |
| `PROMETHEUS_USERNAME` | _(none)_ | Basic-auth username |
| `PROMETHEUS_PASSWORD` | _(none)_ | Basic-auth password |
| `PROMETHEUS_VERIFY_SSL` | `true` | Verify TLS certificates |
| `PROMETHEUS_CA_CERT` | _(none)_ | Path to custom CA bundle for internal PKI |
| `PROMETHEUS_TIMEOUT_SEC` | `30` | HTTP timeout for Mimir queries |
| **SSM** | | |
| `SSM_POLL_INTERVAL_SEC` | `3` | Seconds between SSM status polls |
| `SSM_MAX_WAIT_SEC` | `120` | Max seconds to wait for SSM command |
| **Reporter** | | |
| `REPORTER_TYPE` | `log` | `log` \| `gchat` \| `webhook` |
| `REPORTER_GCHAT_WEBHOOK_URL` | _(required for gchat)_ | GChat incoming webhook URL |
| `REPORTER_WEBHOOK_URL` | _(required for webhook)_ | Generic webhook URL |
| `REPORTER_WEBHOOK_HEADERS` | `{}` | JSON string of extra HTTP headers |
| **API** | | |
| `API_HOST` | `0.0.0.0` | Bind address |
| `API_PORT` | `8080` | Bind port |
| `API_SECRET_TOKEN` | _(none)_ | Bearer token to protect the inbound API |
| **Logging** | | |
| `LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` |
| `LOG_FORMAT` | `json` | `json` \| `console` |

---

## Air-gapped deployment

When the troubleshooter EC2 instance has **no internet access**:

**AWS services** — configure VPC Interface Endpoints and set the overrides:

```bash
USE_VPC_ENDPOINTS=true
VPC_ENDPOINT_EC2=https://vpce-xxxxxxxxxxxx.ec2.us-east-1.vpce.amazonaws.com
VPC_ENDPOINT_SSM=https://vpce-xxxxxxxxxxxx.ssm.us-east-1.vpce.amazonaws.com
VPC_ENDPOINT_STS=https://vpce-xxxxxxxxxxxx.sts.us-east-1.vpce.amazonaws.com
```

Required VPC endpoints:

| Service | Endpoint service name |
|---|---|
| EC2 | `com.amazonaws.<region>.ec2` |
| SSM | `com.amazonaws.<region>.ssm` |
| SSM Messages | `com.amazonaws.<region>.ssmmessages` |
| EC2 Messages | `com.amazonaws.<region>.ec2messages` |
| STS | `com.amazonaws.<region>.sts` |

**Grafana Mimir** — no special routing needed. `PROMETHEUS_URL` is already an
internal URL (e.g. `http://mimir.internal:8080/prometheus`).  For HTTPS with
an internal CA, set `PROMETHEUS_CA_CERT=/etc/ssl/certs/internal-ca.crt` or
`PROMETHEUS_VERIFY_SSL=false`.

For **offline Docker builds** (no internet on the build host):

```bash
# 1. On a machine with internet access, download wheels:
pip download -r requirements.txt -d docker/wheels/

# 2. On the air-gapped host, build from local wheels:
docker build -f docker/Dockerfile.offline -t ec2-troubleshooter:offline .
```

---

## IAM permissions

The EC2 instance running the troubleshooter needs the following IAM policy
(via an instance profile):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2ReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeVolumes",
        "ec2:GetConsoleOutput"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SSMRunCommandReadOnly",
      "Effect": "Allow",
      "Action": [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:DescribeInstanceInformation"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSCallerIdentity",
      "Effect": "Allow",
      "Action": ["sts:GetCallerIdentity"],
      "Resource": "*"
    }
  ]
}
```

**Target instances** (the ones being diagnosed) must also have the
`AmazonSSMManagedInstanceCore` managed policy attached and the SSM agent
running.

---

## SSM command allowlist

All host-level diagnostics are executed via SSM Run Command using the
`AWS-RunShellScript` document.  Only the following **pre-approved, read-only**
commands can be triggered:

| Key | Purpose |
|---|---|
| `cpu_top` | Top CPU-consuming processes (`top -b -n 1`) |
| `load_average` | System load (`/proc/loadavg`, `uptime`) |
| `memory_free` | Memory usage (`free -m`) |
| `memory_vmstat` | VM statistics |
| `disk_usage` | Filesystem usage (`df -hT`) |
| `disk_inodes` | Inode usage (`df -i`) |
| `disk_io_stats` | I/O statistics (`iostat`) |
| `network_connections` | Active connections (`ss -tunap`) |
| `network_stats` | Interface stats |
| `process_list` | Process list (`ps aux --sort=-%cpu`) |
| `zombie_processes` | Zombie process count |
| `systemd_failed` | Failed systemd units |
| `systemd_status` | Systemd overall status |
| `dmesg_errors` | Kernel error messages |
| `journal_errors` | systemd journal errors (last hour) |
| `journal_kernel_oom` | OOM killer events |
| `os_release` | OS version |
| `kernel_version` | Kernel version |
| `ntp_status` | NTP / time sync status |
| `fd_usage` | File descriptor usage |

Any attempt to run a command not in this list returns an error rather than
executing.

---

## Reporters

### `log` (default)

Writes the full formatted report to stdout via structlog.  Ideal for
collecting findings in CloudWatch Logs, Splunk, or any log aggregator.

### `gchat`

Posts a Google Chat Cards v2 message to an incoming webhook URL.

```bash
REPORTER_TYPE=gchat
REPORTER_GCHAT_WEBHOOK_URL=https://chat.googleapis.com/v1/spaces/XXX/messages?key=YYY
```

### `webhook`

POSTs the full JSON report to any HTTP endpoint.  Suitable for Jira, PagerDuty,
ServiceNow, or a custom incident management UI.

```bash
REPORTER_TYPE=webhook
REPORTER_WEBHOOK_URL=https://internal-incident.example.com/api/ingest
REPORTER_WEBHOOK_HEADERS={"Authorization": "Bearer <token>"}
```

---

## Docker

```bash
# Build
docker build -f docker/Dockerfile -t ec2-troubleshooter .

# Run
docker run -p 8080:8080 \
  -e AWS_REGION=us-east-1 \
  -e REPORTER_TYPE=log \
  ec2-troubleshooter
```

With Docker Compose:

```bash
cp .env.example .env
# Edit .env
docker compose -f docker/docker-compose.yml up
```

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=ec2_troubleshooter --cov-report=term-missing

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

---

## Project structure

```
src/ec2_troubleshooter/
├── __init__.py
├── __main__.py               # Entry point
├── config/
│   ├── settings.py           # Pydantic-settings config + VPC endpoint routing
│   └── logging.py            # structlog configuration
├── models/
│   ├── alert.py              # Canonical Alert model
│   └── findings.py           # DiagnosticResult, Finding, InvestigationReport
├── tools/
│   ├── aws_client.py         # boto3 client factory (VPC endpoint aware)
│   ├── ec2_tools.py          # EC2 API read-only tools
│   ├── cloudwatch_tools.py   # CloudWatch metrics tools
│   ├── ssm_tools.py          # SSM Run Command (allowlist enforced)
│   └── tool_server.py        # MCP-style tool dispatch server
├── orchestrator/
│   ├── investigator.py       # Investigation lifecycle orchestrator
│   └── analyzer.py           # Evidence → findings analysis
├── alert/
│   ├── normalizer.py         # Multi-format alert normalizer
│   └── receiver.py           # FastAPI alert receiver
└── reporter/
    ├── base.py               # Reporter interface
    ├── formatter.py          # Text / GChat card / JSON formatters
    ├── log_reporter.py       # Log-based reporter
    ├── gchat.py              # Google Chat reporter
    ├── webhook.py            # Generic webhook reporter
    └── factory.py            # Reporter factory
tests/
docker/
deploy/
```
