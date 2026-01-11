import logging
import os
import re
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, Optional, TypedDict

# Explicit type annotation for modules to satisfy type-checkers
# and handle conditional imports gracefully.
fcntl: ModuleType | None = None
try:
    import fcntl
except ImportError:
    fcntl = None

msvcrt: ModuleType | None = None
if sys.platform == "win32":
    try:
        import msvcrt
    except ImportError:
        msvcrt = None

logger = logging.getLogger(__name__)


class SystemContext(TypedDict):
    """Structured type representing core system architectural facts."""

    binaries: list[str]
    has_gpu: bool
    patterns: list[str]
    active_role: str
    has_install_history: bool


class RoleManager:
    """
    Provides system context for LLM-driven role detection and recommendations.

    Serves as the 'sensing layer' for the system architect. It aggregates factual
    signals (binary presence, hardware capabilities, and minimized shell patterns)
    to provide a synchronized ground truth for AI inference.
    """

    CONFIG_KEY = "CORTEX_SYSTEM_ROLE"

    # Performance: Precompile patterns once at the class level to optimize regex matching
    # performance across repeated CLI executions and prevent redundant overhead.
    _SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
        re.compile(p)
        for p in [
            r"(?i)api[-_]?key\s*[:=]\s*[^\s]+",
            r"(?i)token\s*[:=]\s*[^\s]+",
            r"(?i)password\s*[:=]\s*[^\s]+",
            r"(?i)passwd\s*[:=]\s*[^\s]+",
            r"(?i)Authorization:\s*[^\s]+",
            r"(?i)Bearer\s+[^\s]+",
            r"(?i)X-Api-Key:\s*[^\s]+",
            r"(?i)-H\s+['\"][^'\"]*auth[^'\"]*['\"]",
            r"(?i)export\s+(?:[^\s]*(?:key|token|secret|password|passwd|credential|auth)[^\s]*)=[^\s]+",
            r"(?i)AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)\s*[:=]\s*[^\s]+",
            r"(?i)GOOGLE_APPLICATION_CREDENTIALS\s*[:=]\s*[^\s]+",
            r"(?i)GCP_(?:SERVICE_ACCOUNT|CREDENTIALS)\s*[:=]\s*[^\s]+",
            r"(?i)AZURE_(?:CLIENT_SECRET|TENANT_ID|SUBSCRIPTION_ID)\s*[:=]\s*[^\s]+",
            r"(?i)(?:GITHUB|GITLAB)_TOKEN\s*[:=]\s*[^\s]+",
            r"(?i)docker\s+login.*-p\s+[^\s]+",
            r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"(?i)sshpass\s+-p\s+[^\s]+",
            r"(?i)ssh-add.*-k",
            r"(?i)(?:postgres|mysql|mongodb)://[^@\s]+:[^@\s]+@",
        ]
    )

    def __init__(self, env_path: Path | None = None) -> None:
        """
        Initializes the manager and sets the configuration and history paths.

        Args:
            env_path: Optional Path to the environment file. Defaults to ~/.cortex/.env.
        """
        self.env_file = env_path or (Path.home() / ".cortex" / ".env")
        self.history_db = Path.home() / ".cortex" / "history.db"

    def _get_shell_patterns(self) -> list[str]:
        """
        Senses user intent from shell history while minimizing privacy risk.

        Provides a toggle for history sensing via 'CORTEX_SENSE_HISTORY' env var.
        Uses intent tokenization to strip raw arguments, returning coarse-grained
        activity tokens instead of raw strings to avoid leaking local metadata.

        Returns:
            list[str]: A list of coarse-grained intent tokens (e.g., 'intent:install').
        """
        if os.environ.get("CORTEX_SENSE_HISTORY", "true").lower() == "false":
            return []

        # Maps raw shell verbs to generalized intent categories to prevent data leakage
        intent_map = {
            "apt": "intent:install",
            "pip": "intent:install",
            "npm": "intent:install",
            "kubectl": "intent:k8s",
            "helm": "intent:k8s",
            "docker": "intent:container",
            "git": "intent:version_control",
            "systemctl": "intent:service_mgmt",
            "python": "intent:execution",
        }

        try:
            all_history_lines: list[str] = []
            for history_file in [".bash_history", ".zsh_history"]:
                path = Path.home() / history_file
                if not path.exists():
                    continue

                # errors="ignore" prevents crashes on non-UTF-8 binary data in history files
                all_history_lines.extend(
                    path.read_text(encoding="utf-8", errors="ignore").splitlines()
                )

            trimmed_commands = [l.strip() for l in all_history_lines if l.strip()]
            recent_commands = trimmed_commands[-15:]

            patterns = []
            for cmd in recent_commands:
                if cmd.startswith("cortex role set"):
                    continue

                # Check against precompiled PII/Credential patterns
                if any(p.search(cmd) for p in self._SENSITIVE_PATTERNS):
                    patterns.append("<redacted>")
                    continue

                # Data Minimization: Extract the verb and map to an intent token
                parts = cmd.split()
                if not parts:
                    continue

                verb = parts[0].lower()
                patterns.append(intent_map.get(verb, f"intent:{verb}"))

            return patterns

        except OSError as e:
            logger.warning("Access denied to sensing layer history: %s", e)
            return []
        except Exception as e:
            logger.debug("Unexpected error during shell pattern sensing: %s", e)
            return []

    def get_system_context(self) -> SystemContext:
        """
        Aggregates factual system signals and activity patterns for AI inference.

        Returns:
            SystemContext: Factual architectural context including hardware and signals.
        """
        signals = [
            "nginx",
            "apache2",
            "docker",
            "psql",
            "mysql",
            "redis-server",
            "nvidia-smi",
            "rocm-smi",
            "intel_gpu_top",
            "conda",
            "jupyter",
            "gcc",
            "make",
            "git",
            "go",
            "node",
            "ansible",
            "terraform",
            "kubectl",
            "rustc",
            "cargo",
            "python3",
        ]

        # Use 'signal' as loop variable to avoid shadowing built-in bin() function
        detected_binaries = [signal for signal in signals if shutil.which(signal)]

        has_gpu = any(x in detected_binaries for x in ["nvidia-smi", "rocm-smi", "intel_gpu_top"])
        has_install_history = self.history_db.exists()

        return {
            "binaries": detected_binaries,
            "has_gpu": has_gpu,
            "patterns": self._get_shell_patterns(),
            "active_role": self.get_saved_role() or "undefined",
            "has_install_history": has_install_history,
        }

    def save_role(self, role_slug: str) -> None:
        """
        Persists the system role identifier using an atomic update pattern.

        Args:
            role_slug: The role identifier (e.g., 'data-scientist').
        """
        if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?", role_slug):
            logger.error("Invalid role slug rejected: %r", role_slug)
            raise ValueError(f"Invalid role slug format: {role_slug!r}")

        def modifier(existing_content: str, key: str, value: str) -> str:
            pattern = rf"^(?:export\s+)?{re.escape(key)}\s*=.*$"
            if re.search(pattern, existing_content, flags=re.MULTILINE):
                return re.sub(
                    pattern, lambda _: f"{key}={value}", existing_content, flags=re.MULTILINE
                )
            else:
                if existing_content and not existing_content.endswith("\n"):
                    existing_content += "\n"
                return existing_content + f"{key}={value}\n"

        try:
            self._locked_read_modify_write(self.CONFIG_KEY, role_slug, modifier)
        except Exception as e:
            logger.error("Failed to persist system role: %s", e)
            raise RuntimeError(f"Could not persist role to {self.env_file}") from e

    def get_saved_role(self) -> str | None:
        """
        Reads the active role with tolerant parsing for standard shell file formats.

        Returns:
            str | None: The saved role slug or None if no meaningful value is found.
        """
        if not self.env_file.exists():
            return None

        try:
            # Use errors="replace" to handle decoding issues on corrupted environment files
            content = self.env_file.read_text(encoding="utf-8", errors="replace")

            # Tolerant parsing handles optional 'export', flexible spacing, and quotes
            pattern = rf"^(?:export\s+)?{re.escape(self.CONFIG_KEY)}\s*=\s*['\"]?(.*?)['\"]?$"
            match = re.search(pattern, content, re.MULTILINE)

            if not match:
                return None

            value = match.group(1).strip()
            return value if value else None
        except Exception as e:
            logger.error("Error reading saved role: %s", e)
            return None

    def _locked_read_modify_write(
        self,
        key: str,
        value: str,
        modifier_func: Callable[[str, str, str], str],
        target_file: Path | None = None,
    ) -> None:
        """
        Performs a thread-safe, atomic file update with cross-platform locking support.

        Implements POSIX advisory locking (fcntl) or Windows byte-range locking
        (msvcrt) to prevent lost updates. Employs a write-to-temporary-and-swap
        pattern with explicit cleanup to ensure file integrity.
        """
        target = target_file or self.env_file
        target.parent.mkdir(parents=True, exist_ok=True)

        lock_file = target.with_suffix(".lock")
        lock_file.touch(exist_ok=True)
        try:
            lock_file.chmod(0o600)
        except OSError:
            pass

        temp_file = target.with_suffix(".tmp")
        try:
            with open(lock_file, "r+") as lock_fd:
                # Platform-aware concurrency protection
                if fcntl:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                elif msvcrt:
                    msvcrt.locking(lock_fd.fileno(), msvcrt.LK_LOCK, 1)

                try:
                    existing = (
                        target.read_text(encoding="utf-8", errors="replace")
                        if target.exists()
                        else ""
                    )
                    updated = modifier_func(existing, key, value)

                    temp_file.write_text(updated, encoding="utf-8")
                    temp_file.chmod(0o600)

                    # Atomic swap guaranteed by the OS replace operation
                    temp_file.replace(target)
                finally:
                    if fcntl:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    elif msvcrt:
                        msvcrt.locking(lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            # Cleanup mechanism to remove orphaned temporary files on failure
            if temp_file.exists():
                try:
                    os.remove(temp_file)
                except OSError:
                    pass
