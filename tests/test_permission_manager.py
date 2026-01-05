import os
from unittest.mock import MagicMock, patch

import pytest

from cortex.permission_manager import PermissionManager


@pytest.fixture
def manager():
    """Create a permission manager instance with a standardized path."""
    # Ensure the path works correctly on both Windows and Linux systems
    return PermissionManager(os.path.normpath("/dummy/path"))


def test_diagnose_finds_root_files(manager):
    """Confirm that the tool correctly identifies files owned by root."""
    # Intercept system tools within the permission manager module for testing
    with (
        patch("cortex.permission_manager.os.walk") as mock_walk,
        patch("cortex.permission_manager.os.stat") as mock_stat,
    ):

        base = os.path.normpath("/dummy/path")
        locked_file = os.path.join(base, "locked.txt")

        # Simulate a folder containing one root-owned file and one user file
        mock_walk.return_value = [(base, [], ["locked.txt", "normal.txt"])]

        root_stat = MagicMock()
        root_stat.st_uid = 0  # Identify file as owned by root
        user_stat = MagicMock()
        user_stat.st_uid = 1000  # Identify file as owned by regular user

        mock_stat.side_effect = [root_stat, user_stat]

        results = manager.diagnose()

        assert len(results) == 1
        assert os.path.normpath(locked_file) in [os.path.normpath(r) for r in results]


def test_check_compose_config_suggests_fix(manager):
    """Confirm that a tip is shown when the user setting is missing from configuration."""
    # Intercept file existence checks and console output within the module
    with (
        patch("cortex.permission_manager.os.path.exists", return_value=True),
        patch(
            "builtins.open",
            MagicMock(
                return_value=MagicMock(__enter__=lambda s: MagicMock(read=lambda: "version: '3'"))
            ),
        ),
        patch("cortex.permission_manager.console.print") as mock_console,
    ):
        manager.check_compose_config()

        # Check that the help message was actually displayed to the user
        mock_console.assert_called_once()
        call_args = mock_console.call_args[0][0]
        assert "user:" in call_args
        assert "docker-compose.yml" in call_args


@patch("cortex.permission_manager.subprocess.run")
@patch("cortex.permission_manager.platform.system", return_value="Linux")
def test_fix_permissions_executes_chown(mock_platform, mock_run, manager):
    """Confirm that the ownership command is triggered with the correct settings."""
    # Simulate user IDs which might not exist on Windows development environments
    with (
        patch("cortex.permission_manager.os.getuid", create=True, return_value=1000),
        patch("cortex.permission_manager.os.getgid", create=True, return_value=1000),
    ):

        test_file = os.path.normpath("/path/to/file1.txt")
        files = [test_file]
        success = manager.fix_permissions(files)

        assert success is True
        # Verify the command includes the correct ID, file path, and a 60 second time limit
        mock_run.assert_called_once_with(
            ["sudo", "chown", "1000:1000", test_file], check=True, capture_output=True, timeout=60
        )
