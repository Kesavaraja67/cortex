"""
Docker Permission Management Module.

This module provides tools to diagnose and repair file ownership issues
that occur when Docker containers create files in host-mounted directories.
"""

import os
import platform
import subprocess

from cortex.branding import console

# Standard project directories to ignore during scans
EXCLUDED_DIRS = {
    "venv",
    ".venv",
    ".git",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
}


class PermissionManager:
    """Manages and fixes Docker-related file permission issues for bind mounts."""

    def __init__(self, base_path: str):
        """Initialize the manager with the project base path.

        Args:
            base_path: The root directory of the project to scan.
        """
        self.base_path = base_path
        # Cache current system IDs to avoid multiple system calls
        self.host_uid = os.getuid() if platform.system() != "Windows" else 1000
        self.host_gid = os.getgid() if platform.system() != "Windows" else 1000

    def diagnose(self) -> list[str]:
        """Scans for files not owned by the current host user.

        Returns:
            list[str]: A list of full file paths with ownership mismatches.
        """
        mismatched_files = []
        for root, dirs, files in os.walk(self.base_path):
            # Efficiently skip excluded directories by modifying dirs in-place
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

            for name in files:
                full_path = os.path.join(root, name)
                try:
                    # Catch any file not owned by the current user
                    # This handles both root (0) and other container-specific UIDs
                    if os.stat(full_path).st_uid != self.host_uid:
                        mismatched_files.append(full_path)
                except (PermissionError, FileNotFoundError):
                    continue
        return mismatched_files

    def generate_compose_settings(self) -> str:
        """Generates the recommended user mapping for docker-compose.yml.

        Returns:
            str: A formatted YAML snippet for the user directive.
        """
        # Provides the exact configuration needed to prevent future issues
        return (
            f'    user: "{self.host_uid}:{self.host_gid}"\n'
            "    # Or for better portability across different machines:\n"
            '    # user: "${UID}:${GID}"'
        )

    def check_compose_config(self) -> None:
        """Checks if docker-compose.yml contains correct user mapping."""
        compose_path = os.path.join(self.base_path, "docker-compose.yml")
        if os.path.exists(compose_path):
            try:
                with open(compose_path, encoding="utf-8") as f:
                    content = f.read()

                if "user:" not in content:
                    console.print(
                        "\n[bold yellow]💡 Recommended Docker-Compose settings:[/bold yellow]"
                    )
                    console.print(self.generate_compose_settings())
            except Exception:
                # Silently fail if file is unreadable to avoid blocking the main flow
                pass

    def fix_permissions(self, execute: bool = False) -> bool:
        """Attempts to change ownership of files back to the host user.

        Args:
            execute: If True, applies changes. If False, performs a dry-run.

        Returns:
            bool: True if repairs succeeded or no mismatches found, False otherwise.
        """
        # 1. Run the diagnosis internally to get the list of files
        mismatches = self.diagnose()

        if not mismatches:
            console.print("[bold green]✅ No permission mismatches detected.[/bold green]")
            return True

        # 2. Handle Dry-Run mode (The "Real Implementation" of the flag)
        if not execute:
            console.print(
                f"\n[bold cyan]📋 [Dry-run][/bold cyan] Found {len(mismatches)} files owned by root/other UIDs."
            )
            for path in mismatches[:5]:
                console.print(f"  • {path}")
            if len(mismatches) > 5:
                console.print(f"  ... and {len(mismatches) - 5} more.")

            console.print("\n[bold yellow]👉 Run with --execute to apply repairs.[/bold yellow]")
            return True

        # 3. Handle Real Execution (Only runs if execute=True)
        if platform.system() == "Windows":
            console.print("[red]Error: Permission repairs are only supported on Linux/WSL.[/red]")
            return False

        console.print(
            f"[bold core_blue]🔧 Applying repairs to {len(mismatches)} paths...[/bold core_blue]"
        )
        try:
            subprocess.run(
                ["sudo", "chown", f"{self.host_uid}:{self.host_gid}"] + mismatches,
                check=True,
                capture_output=True,
                timeout=60,
            )
            console.print("[bold green]✅ Ownership reclaimed successfully![/bold green]")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, PermissionError) as e:
            console.print(f"[bold red]❌ Failed to fix permissions: {str(e)}[/bold red]")
            return False
