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
│   • Calls EC2ToolServer.run_standard_suite(instance_id)                  │
│   • Passes raw results through EvidenceAnalyzer                          │
│   • Assembles InvestigationReport                                        │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  EC2 Tool Server  (MCP-style bounded interface)                          │
│                                                                          │
│  ┌─────────────────────┐  ┌────────────────────────┐  ┌───────────────┐ │
│  │  EC2 Tools          │  │  CloudWatch Tools       │  │  SSM Tools    │ │
│  │  describe_instance  │  │  cpu_utilization        │  │  Allowlist    │ │
│  │  get_instance_status│  │  disk_io                │  │  (25+ cmds)   │ │
│  │  describe_volumes   │  │  network_io             │  │  read-only    │ │
│  │  get_console_output │  │  status_check_metrics   │  │  shell cmds   │ │
│  └──────────┬──────────┘  └──────────┬─────────────┘  └───────┬───────┘ │
│             │  AWS EC2 API           │  CloudWatch API         │ SSM     │
└─────────────┼────────────────────────┼─────────────────────────┼─────────┘
              │                        │                         │
              │  (VPC Interface Endpoints in air-gapped envs)    │
              ▼                        ▼                         ▼
         AWS EC2 API           AWS CloudWatch            AWS SSM Run Command
```

### Key design decisions

| Decision | Rationale |
|---|---|
| **MCP-style tool server boundary** | The orchestrator never talks to AWS directly. All AWS calls go through the `EC2ToolServer`, which enforces the read-only and allowlist contracts. |
| **SSM allowlist** | Only 25 pre-approved, audited read-only shell commands can run via SSM. No freeform shell. No arbitrary command construction. |
| **No SSH** | All host-level commands go through AWS SSM Run Command (requires SSM agent + IAM role). No ports to open, no keys to manage. |
| **VPC endpoint support** | Every boto3 client accepts an `endpoint_url` override so all traffic stays within the VPC, satisfying air-gapped / no-internet requirements. |
| **Generic diagnostics only** | No app-specific logic (Airflow, Kafka, etc.). The tool layer only answers OS/infrastructure questions: CPU, memory, disk, network, processes, kernel errors. |
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
| `USE_VPC_ENDPOINTS` | `false` | Route all SDK calls through VPC endpoints |
| `VPC_ENDPOINT_EC2` | _(none)_ | EC2 VPC interface endpoint URL |
| `VPC_ENDPOINT_SSM` | _(none)_ | SSM VPC interface endpoint URL |
| `VPC_ENDPOINT_CLOUDWATCH` | _(none)_ | CloudWatch VPC interface endpoint URL |
| `VPC_ENDPOINT_STS` | _(none)_ | STS VPC interface endpoint URL |
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

When the troubleshooter EC2 instance has **no internet access**, configure
VPC Interface Endpoints for the required AWS services and set the corresponding
environment variables:

```bash
USE_VPC_ENDPOINTS=true
VPC_ENDPOINT_EC2=https://vpce-xxxxxxxxxxxx.ec2.us-east-1.vpce.amazonaws.com
VPC_ENDPOINT_SSM=https://vpce-xxxxxxxxxxxx.ssm.us-east-1.vpce.amazonaws.com
VPC_ENDPOINT_CLOUDWATCH=https://vpce-xxxxxxxxxxxx.monitoring.us-east-1.vpce.amazonaws.com
VPC_ENDPOINT_STS=https://vpce-xxxxxxxxxxxx.sts.us-east-1.vpce.amazonaws.com
```

Required VPC endpoints:

| Service | Endpoint service name |
|---|---|
| EC2 | `com.amazonaws.<region>.ec2` |
| SSM | `com.amazonaws.<region>.ssm` |
| SSM Messages | `com.amazonaws.<region>.ssmmessages` |
| EC2 Messages | `com.amazonaws.<region>.ec2messages` |
| CloudWatch | `com.amazonaws.<region>.monitoring` |
| STS | `com.amazonaws.<region>.sts` |

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
