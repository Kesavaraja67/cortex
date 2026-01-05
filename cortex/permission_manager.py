import os
import platform
import subprocess

from cortex.branding import console  # Import console for the colored output


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
            list[str]: A list of full file paths that have permission mismatches.
        """
        root_owned_files = []
        for root, _, files in os.walk(self.base_path):
            # Skip virtual environment and git folders to save time
            if "venv" in root or ".git" in root:
                continue
            for name in files:
                full_path = os.path.join(root, name)
                try:
                    # Check if the file is owned by root (UID 0)
                    if os.stat(full_path).st_uid == 0:
                        root_owned_files.append(full_path)
                except (PermissionError, FileNotFoundError):
                    continue
        return root_owned_files

    def check_compose_config(self) -> None:
        """Checks if docker-compose.yml uses the correct user mapping.

        This scans for the 'user:' key in the docker-compose file and suggests
        a fix if it is missing to prevent future permission lockouts.
        """
        compose_path = os.path.join(self.base_path, "docker-compose.yml")
        if os.path.exists(compose_path):
            try:
                # Adding encoding='utf-8' is a best practice for cross-platform tools
                with open(compose_path, encoding="utf-8") as f:
                    content = f.read()
                    if "user:" not in content:
                        console.print(
                            "\n[bold yellow]💡 Tip: To prevent future lockouts, add "
                            "'user: \"${UID}:${GID}\"' to your services in "
                            "docker-compose.yml.[/bold yellow]"
                        )
            except Exception:
                # Silently fail if file cannot be read to avoid interrupting CLI flow
                pass

    def fix_permissions(self, file_paths: list[str]) -> bool:
        """Attempts to change ownership of files back to the current user.

        Args:
            file_paths: List of full paths to files requiring ownership changes.

        Returns:
            bool: True if the chown command executed successfully, False otherwise.

        Raises:
            OSError: If the system cannot execute the subprocess command.
        """
        if not file_paths:
            return True

        # Permissions work differently on Windows; sudo chown is a Linux/Unix command
        if platform.system() == "Windows":
            return False

        try:
            uid = os.getuid()
            gid = os.getgid()
            # Combine files into one command for efficiency.
            # capture_output=True keeps the terminal clean from unnecessary command output.
            subprocess.run(
                ["sudo", "chown", f"{uid}:{gid}"] + file_paths, check=True, capture_output=True
            )
            return True
        except (subprocess.CalledProcessError, PermissionError):
            return False
