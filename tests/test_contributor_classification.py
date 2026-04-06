"""
Tests for contributor kind classification and routing.

Validates that:
  - Log signals (app_log_errors, dag_log_errors) are NOT queried from Mimir
  - Infra metrics (cpu, memory, disk) are marked as covered by node_metrics
  - App metrics (everything else with a valid PromQL name) are queried from Mimir
"""

from __future__ import annotations

from unittest.mock import MagicMock

from ec2_troubleshooter.models.alert import (
    Alert,
    AlertSeverity,
    AnomalyContributor,
    ContributorKind,
    classify_contributor,
)
from ec2_troubleshooter.models.findings import (
    DiagnosticResult,
    DiagnosticStatus,
    FindingSeverity,
    InstanceInvestigation,
)
from ec2_troubleshooter.orchestrator.analyzer import EvidenceAnalyzer
from ec2_troubleshooter.orchestrator.investigator import InvestigationOrchestrator

# ── classify_contributor ───────────────────────────────────────────────────

class TestClassifyContributor:
    # Log signals
    def test_app_log_errors_is_log_signal(self):
        assert classify_contributor("app_log_errors") == ContributorKind.LOG_SIGNAL

    def test_dag_log_errors_is_log_signal(self):
        assert classify_contributor("dag_log_errors") == ContributorKind.LOG_SIGNAL

    # Infra metrics
    def test_cpu_is_infra(self):
        assert classify_contributor("cpu") == ContributorKind.INFRA_METRIC

    def test_cpu_usage_pct_is_infra(self):
        assert classify_contributor("cpu_usage_pct") == ContributorKind.INFRA_METRIC

    def test_memory_is_infra(self):
        assert classify_contributor("memory") == ContributorKind.INFRA_METRIC

    def test_memory_used_bytes_is_infra(self):
        assert classify_contributor("memory_used_bytes") == ContributorKind.INFRA_METRIC

    def test_mem_is_infra(self):
        assert classify_contributor("mem") == ContributorKind.INFRA_METRIC

    def test_disk_is_infra(self):
        assert classify_contributor("disk") == ContributorKind.INFRA_METRIC

    def test_disk_used_pct_is_infra(self):
        assert classify_contributor("disk_used_pct") == ContributorKind.INFRA_METRIC

    def test_network_is_infra(self):
        assert classify_contributor("network") == ContributorKind.INFRA_METRIC

    def test_load_is_infra(self):
        assert classify_contributor("load") == ContributorKind.INFRA_METRIC

    def test_swap_is_infra(self):
        assert classify_contributor("swap") == ContributorKind.INFRA_METRIC

    # App metrics
    def test_kafka_lag_is_app_metric(self):
        assert classify_contributor("kafka_consumer_lag") == ContributorKind.APP_METRIC

    def test_jvm_heap_is_app_metric(self):
        assert classify_contributor("jvm_heap_used_bytes") == ContributorKind.APP_METRIC

    def test_http_errors_is_app_metric(self):
        assert classify_contributor("http_requests_errors_total") == ContributorKind.APP_METRIC

    def test_custom_metric_is_app_metric(self):
        assert classify_contributor("mimir_ingester_active_series") == ContributorKind.APP_METRIC

    # Unknown / non-metric strings
    def test_spaces_is_unknown(self):
        assert classify_contributor("App logs") == ContributorKind.UNKNOWN

    def test_empty_is_unknown(self):
        assert classify_contributor("") == ContributorKind.UNKNOWN


# ── AIOps normalizer classification ───────────────────────────────────────

class TestNormalizerClassification:
    def test_app_log_errors_contributor_classified(self):
        from ec2_troubleshooter.alert.normalizer import AlertNormalizer
        payload = {
            "title": "AIOps ALERT: platform-mimir (use1)",
            "metric_contributors": "app_log_errors",
            "app_log_errors": 574,
            "affected_instances": ["host-1"],
            "health": 70.0,
            "failure": 86.1,
        }
        alert = AlertNormalizer().normalize(payload)
        c = next(c for c in alert.contributors if c.metric_name == "app_log_errors")
        assert c.kind == ContributorKind.LOG_SIGNAL
        assert c.value == 574.0

    def test_dag_log_errors_contributor_classified(self):
        from ec2_troubleshooter.alert.normalizer import AlertNormalizer
        payload = {
            "title": "AIOps ALERT: airflow-workers (use1)",
            "metric_contributors": "dag_log_errors",
            "dag_log_errors": 23,
            "affected_instances": ["host-1"],
            "health": 60.0,
            "failure": 90.0,
        }
        alert = AlertNormalizer().normalize(payload)
        c = next(c for c in alert.contributors if c.metric_name == "dag_log_errors")
        assert c.kind == ContributorKind.LOG_SIGNAL
        assert c.value == 23.0

    def test_cpu_contributor_classified_as_infra(self):
        from ec2_troubleshooter.alert.normalizer import AlertNormalizer
        payload = {
            "title": "AIOps ALERT: kafka-brokers (use1)",
            "metric_contributors": "cpu",
            "affected_instances": ["host-1"],
            "health": 50.0,
            "failure": 95.0,
        }
        alert = AlertNormalizer().normalize(payload)
        c = next(c for c in alert.contributors if c.metric_name == "cpu")
        assert c.kind == ContributorKind.INFRA_METRIC

    def test_app_metric_contributor_classified(self):
        from ec2_troubleshooter.alert.normalizer import AlertNormalizer
        payload = {
            "title": "AIOps ALERT: kafka-brokers (use1)",
            "metric_contributors": "kafka_consumer_lag_seconds",
            "affected_instances": ["host-1"],
            "health": 70.0,
            "failure": 80.0,
        }
        alert = AlertNormalizer().normalize(payload)
        c = next(c for c in alert.contributors if c.metric_name == "kafka_consumer_lag_seconds")
        assert c.kind == ContributorKind.APP_METRIC


# ── Orchestrator routing ───────────────────────────────────────────────────

class TestOrchestratorRouting:
    def _make_orchestrator(self):
        mock_server = MagicMock()
        ok = DiagnosticResult(
            tool_name="ec2:describe_instance",
            status=DiagnosticStatus.OK,
            summary="ok",
            metrics={"state": "running", "private_ip": "10.0.1.5"},
        )
        mock_server.call.return_value = ok
        mock_server.run_standard_suite.return_value = [ok]
        return InvestigationOrchestrator(mock_server), mock_server

    def test_log_signal_NOT_queried_from_mimir(self):
        orch, mock_server = self._make_orchestrator()
        alert = Alert(
            alert_id="a1",
            source="aiops_archetype",
            title="t",
            severity=AlertSeverity.HIGH,
            instance_ids=["i-abc"],
            contributors=[
                AnomalyContributor(
                    metric_name="app_log_errors",
                    kind=ContributorKind.LOG_SIGNAL,
                    value=574.0,
                )
            ],
        )
        orch.investigate(alert)
        # prometheus:contributor_metric must NOT have been called
        calls = [str(c) for c in mock_server.call.call_args_list]
        assert not any("contributor_metric" in c for c in calls)

    def test_infra_metric_NOT_queried_from_mimir(self):
        orch, mock_server = self._make_orchestrator()
        alert = Alert(
            alert_id="a2",
            source="aiops_archetype",
            title="t",
            severity=AlertSeverity.HIGH,
            instance_ids=["i-abc"],
            contributors=[
                AnomalyContributor(
                    metric_name="cpu",
                    kind=ContributorKind.INFRA_METRIC,
                )
            ],
        )
        orch.investigate(alert)
        calls = [str(c) for c in mock_server.call.call_args_list]
        assert not any("contributor_metric" in c for c in calls)

    def test_app_metric_IS_queried_from_mimir(self):
        orch, mock_server = self._make_orchestrator()
        mock_server.call.side_effect = lambda inst_id, tool, **kw: DiagnosticResult(
            tool_name=tool, status=DiagnosticStatus.OK, summary="ok",
            metrics={"state": "running", "private_ip": "10.0.1.5"},
        )
        alert = Alert(
            alert_id="a3",
            source="aiops_archetype",
            title="t",
            severity=AlertSeverity.HIGH,
            instance_ids=["i-abc"],
            contributors=[
                AnomalyContributor(
                    metric_name="kafka_consumer_lag_seconds",
                    kind=ContributorKind.APP_METRIC,
                )
            ],
        )
        orch.investigate(alert)
        calls = [str(c) for c in mock_server.call.call_args_list]
        assert any("contributor_metric" in c for c in calls)


# ── Analyzer findings ──────────────────────────────────────────────────────

class TestLogSignalFindings:
    def test_high_app_log_errors_finding(self):
        result = DiagnosticResult(
            tool_name="log_signal:app_log_errors",
            status=DiagnosticStatus.DEGRADED,
            summary="App log errors: 574 error(s) reported in alert",
            metrics={"metric": "app_log_errors", "kind": "log_signal", "count": 574.0},
        )
        inv = InstanceInvestigation(instance_id="i-001", diagnostics=[result])
        EvidenceAnalyzer().analyze(inv)
        log_findings = [f for f in inv.findings if f.category == "app_logs"]
        assert len(log_findings) == 1
        assert log_findings[0].severity == FindingSeverity.HIGH
        assert "574" in log_findings[0].message

    def test_dag_log_errors_finding_mentions_airflow(self):
        result = DiagnosticResult(
            tool_name="log_signal:dag_log_errors",
            status=DiagnosticStatus.DEGRADED,
            summary="Airflow DAG log errors: 23 error(s) reported in alert",
            metrics={"metric": "dag_log_errors", "kind": "log_signal", "count": 23.0},
        )
        inv = InstanceInvestigation(instance_id="i-002", diagnostics=[result])
        EvidenceAnalyzer().analyze(inv)
        log_findings = [f for f in inv.findings if f.category == "app_logs"]
        assert len(log_findings) == 1
        assert "DAG" in log_findings[0].message or "Airflow" in log_findings[0].recommendation
        assert "airflow" in log_findings[0].recommendation.lower()

    def test_zero_log_errors_no_finding(self):
        result = DiagnosticResult(
            tool_name="log_signal:app_log_errors",
            status=DiagnosticStatus.OK,
            summary="App log errors: 0",
            metrics={"metric": "app_log_errors", "kind": "log_signal", "count": 0.0},
        )
        inv = InstanceInvestigation(instance_id="i-003", diagnostics=[result])
        EvidenceAnalyzer().analyze(inv)
        log_findings = [f for f in inv.findings if f.category == "app_logs"]
        assert len(log_findings) == 0

    def test_medium_severity_below_100(self):
        result = DiagnosticResult(
            tool_name="log_signal:app_log_errors",
            status=DiagnosticStatus.DEGRADED,
            summary="App log errors: 42 error(s) reported in alert",
            metrics={"metric": "app_log_errors", "kind": "log_signal", "count": 42.0},
        )
        inv = InstanceInvestigation(instance_id="i-004", diagnostics=[result])
        EvidenceAnalyzer().analyze(inv)
        log_findings = [f for f in inv.findings if f.category == "app_logs"]
        assert log_findings[0].severity == FindingSeverity.MEDIUM


class TestAppMetricFindings:
    def test_app_metric_info_finding(self):
        result = DiagnosticResult(
            tool_name="prometheus:contributor:kafka_consumer_lag_seconds",
            status=DiagnosticStatus.OK,
            summary="kafka_consumer_lag_seconds: 8500.0",
            metrics={"metric": "kafka_consumer_lag_seconds", "result": 8500.0},
        )
        inv = InstanceInvestigation(instance_id="i-005", diagnostics=[result])
        EvidenceAnalyzer().analyze(inv)
        app_findings = [f for f in inv.findings if f.category == "app_metric"]
        assert len(app_findings) == 1
        assert app_findings[0].severity == FindingSeverity.INFO
        assert "kafka_consumer_lag_seconds" in app_findings[0].message
