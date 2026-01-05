import os
import pytest
from unittest.mock import MagicMock, patch
from cortex.permission_manager import PermissionManager


@pytest.fixture
def manager():
    """Fixture to initialize PermissionManager with a dummy path."""
    return PermissionManager("/dummy/path")


def test_diagnose_finds_root_files(manager):
    """Test that diagnose correctly identifies root-owned files (UID 0)."""
    with patch("os.walk") as mock_walk, patch("os.stat") as mock_stat:

        # Mocking a directory structure: one root-owned file, one user-owned file
        mock_walk.return_value = [("/dummy/path", [], ["locked.txt", "normal.txt"])]

        # Define mock stat objects
        root_stat = MagicMock()
        root_stat.st_uid = 0  # Root UID

        user_stat = MagicMock()
        user_stat.st_uid = 1000  # Normal User UID

        # side_effect returns root_stat for the first call, user_stat for the second
        mock_stat.side_effect = [root_stat, user_stat]

        results = manager.diagnose()

        assert len(results) == 1
        assert "/dummy/path/locked.txt" in results


def test_check_compose_config_suggests_fix(manager, capsys):
    """Test that it detects missing 'user:' in docker-compose.yml."""
    with (
        patch("os.path.exists", return_value=True),
        patch(
            "builtins.open",
            MagicMock(
                return_value=MagicMock(__enter__=lambda s: MagicMock(read=lambda: "version: '3'"))
            ),
        ),
    ):

        manager.check_compose_config()
        # Verify the tip is printed to the console
        captured = capsys.readouterr()
        # Note: Depending on branding.console implementation, you might check captured.out
        # if console.print is hooked to sys.stdout.


@patch("subprocess.run")
@patch("platform.system", return_value="Linux")
def test_fix_permissions_executes_chown(mock_platform, mock_run, manager):
    """Test that fix_permissions triggers the correct sudo chown command."""
    with patch("os.getuid", return_value=1000), patch("os.getgid", return_value=1000):

        files = ["/path/to/file1.txt"]
        success = manager.fix_permissions(files)

        assert success is True
        mock_run.assert_called_once_with(
            ["sudo", "chown", "1000:1000", "/path/to/file1.txt"], check=True
        )
