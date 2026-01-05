import os
import platform
import subprocess

from cortex.branding import console


class PermissionManager:
    """Manages and fixes Docker-related file permission issues for bind mounts."""

    def __init__(self, base_path: str):
        """Initialize the manager with the project base path.

        Args:
            base_path: The root directory of the project to scan.
        """
        self.base_path = base_path

    def diagnose(self) -> list[str]:
        """Scans the directory for files owned by root (UID 0).

        Returns:
            A list of full file paths that have permission mismatches.
        """
        root_owned_files = []
        for root, _, files in os.walk(self.base_path):
            # Split the path to check each directory name individually
            path_parts = root.split(os.sep)

            # Skip folders that typically contain many files but do not need checking
            if "venv" in path_parts or ".venv" in path_parts or ".git" in path_parts:
                continue

            for name in files:
                full_path = os.path.join(root, name)
                try:
                    # Check if the file ownership belongs to the root user
                    if os.stat(full_path).st_uid == 0:
                        root_owned_files.append(full_path)
                except (PermissionError, FileNotFoundError):
                    continue
        return root_owned_files

    def check_compose_config(self) -> None:
        """Checks if docker-compose.yml uses the correct user mapping."""
        compose_path = os.path.join(self.base_path, "docker-compose.yml")
        if os.path.exists(compose_path):
            try:
                with open(compose_path, encoding="utf-8") as f:
                    content = f.read()
                    # Suggest a configuration tip if the user setting is missing
                    if "user:" not in content:
                        console.print(
                            "\n[bold yellow]💡 Tip: To prevent future lockouts, add "
                            "'user: \"${UID}:${GID}\"' to your services in "
                            "docker-compose.yml.[/bold yellow]"
                        )
            except Exception:
                pass

    def fix_permissions(self, file_paths: list[str]) -> bool:
        """Attempts to change ownership of files back to the current user.

        Args:
            file_paths: List of full paths to files requiring ownership changes.

        Returns:
            True if the command executed successfully, False otherwise.
        """
        if not file_paths:
            return True

        if platform.system() == "Windows":
            return False

        try:
            uid = os.getuid()
            gid = os.getgid()

            # Set a 60 second time limit to ensure the command does not hang
            subprocess.run(
                ["sudo", "chown", f"{uid}:{gid}"] + file_paths,
                check=True,
                capture_output=True,
                timeout=60,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, PermissionError):
            return False
