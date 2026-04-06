"""Tests for SSMTools allowlist enforcement."""

from __future__ import annotations

import pytest

from ec2_troubleshooter.tools.ssm_tools import ALLOWLISTED_COMMANDS


class TestAllowlist:
    def test_allowlist_not_empty(self):
        assert len(ALLOWLISTED_COMMANDS) > 0

    def test_known_commands_present(self):
        expected = {
            "cpu_top",
            "memory_free",
            "disk_usage",
            "disk_inodes",
            "process_list",
            "systemd_failed",
            "dmesg_errors",
            "journal_errors",
            "network_connections",
        }
        assert expected.issubset(set(ALLOWLISTED_COMMANDS.keys()))

    def test_commands_are_strings(self):
        for key, cmd in ALLOWLISTED_COMMANDS.items():
            assert isinstance(cmd, str), f"Command '{key}' is not a string"
            assert len(cmd) > 0, f"Command '{key}' is empty"

    def test_no_dangerous_patterns(self):
        """Ensure no obviously dangerous commands are in the allowlist."""
        dangerous = ["rm ", "mkfs", "dd if=", "chmod 777", "wget ", "curl ", "> /dev/"]
        for key, cmd in ALLOWLISTED_COMMANDS.items():
            for pattern in dangerous:
                assert pattern not in cmd, (
                    f"Dangerous pattern '{pattern}' found in allowlisted command '{key}': {cmd}"
                )

    def test_unknown_command_raises_key_error(self):
        """SSMTools.run_diagnostic must raise KeyError for non-allowlisted commands."""
        from unittest.mock import MagicMock

        from ec2_troubleshooter.config.settings import Settings
        from ec2_troubleshooter.tools.ssm_tools import SSMTools

        mock_factory = MagicMock()
        settings = Settings()
        tools = SSMTools(mock_factory, settings)
        with pytest.raises(KeyError):
            tools.run_diagnostic("i-test", "arbitrary_shell_command")
