"""
Enhanced command execution module with security fixes and reliability improvements.

SECURITY: This module replaces the vulnerable subprocess.run(cmd, shell=True) pattern
with secure list-based command execution to prevent shell injection attacks.
"""

import subprocess
import shlex
import logging
import time
from typing import Optional, List

# Default timeout for commands (2 minutes)
DEFAULT_TIMEOUT = 120

# Retry configuration
MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1.0  # seconds


def run_command(
    base_command: str,
    args: List[str],
    profile: Optional[str] = None,
    context: Optional[str] = None,
    check_rc: bool = True,
    suppress_error: bool = False,
    timeout: float = DEFAULT_TIMEOUT
) -> Optional[str]:
    """
    Safely runs a command WITHOUT shell=True to prevent shell injection.

    SECURITY: Uses list-based subprocess execution with shell=False.
    No string concatenation of untrusted input. Arguments passed as separate list items.

    Args:
        base_command: Base command ('kubectl', 'aws')
        args: List of arguments (pre-split, no shell parsing needed)
        profile: AWS profile to inject (for 'aws' commands)
        context: kubectl context to inject (for 'kubectl' commands)
        check_rc: Raise exception on non-zero return code
        suppress_error: Suppress error logging
        timeout: Command timeout in seconds (default: 120s)

    Returns:
        Command stdout as string, or None on failure

    Security Notes:
        - Uses shell=False to prevent command injection
        - Arguments passed as separate list items (no shell parsing)
        - Special characters in arguments are safely handled

    Reliability Features:
        - Automatic retry with exponential backoff (3 attempts)
        - Timeout handling (kills hung processes)
        - Structured error messages
    """
    cmd_list = [base_command]

    # Inject context/profile at start of argument list
    if base_command == "kubectl" and context:
        cmd_list.extend(["--context", context])
    elif base_command == "aws" and profile:
        cmd_list.extend(["--profile", profile])

    cmd_list.extend(args)

    # Retry loop with exponential backoff
    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            if attempt > 0:
                # Exponential backoff: 1s, 2s, 4s
                delay = INITIAL_RETRY_DELAY * (2 ** (attempt - 1))
                logging.debug(f"Retrying command (attempt {attempt + 1}/{MAX_RETRIES}) after {delay}s delay")
                time.sleep(delay)

            logging.debug(f"Running command: {' '.join(cmd_list)}")

            result = subprocess.run(
                cmd_list,  # List, not string - prevents shell injection
                shell=False,  # CRITICAL: Never use shell=True
                capture_output=True,
                text=True,
                check=check_rc,
                encoding='utf-8',
                timeout=timeout
            )

            return result.stdout.strip()

        except subprocess.TimeoutExpired as e:
            last_error = e
            if not suppress_error:
                logging.error(f"Command timed out after {timeout}s: {' '.join(cmd_list)}")
            # Don't retry timeouts - they likely won't succeed
            return None

        except FileNotFoundError:
            # Don't retry FileNotFoundError - command doesn't exist
            if not suppress_error:
                logging.error(f"Command not found: {base_command}. Ensure {base_command} is installed and in PATH.")
            return None

        except subprocess.CalledProcessError as e:
            last_error = e

            # Parse common error patterns for better diagnostics
            stderr_output = e.stderr.strip() if e.stderr else "(no stderr)"
            error_message = _parse_error_message(base_command, e.returncode, stderr_output)

            # Check if error is retryable
            is_retryable = _is_retryable_error(e.returncode, stderr_output)

            if not is_retryable or attempt == MAX_RETRIES - 1:
                # Don't retry or last attempt - log error
                if not suppress_error:
                    logging.error(f"Command failed (rc={e.returncode}): {' '.join(cmd_list)}")
                    logging.error(f"Error: {error_message}")
                return None
            else:
                # Retryable error - continue to next attempt
                logging.debug(f"Retryable error (rc={e.returncode}), will retry: {error_message}")

        except Exception as e:
            last_error = e
            if not suppress_error:
                logging.error(f"Unexpected error running command '{' '.join(cmd_list)}': {e}")
            return None

    # All retries exhausted
    return None


def run_cmd(
    cmd: str,
    profile: Optional[str] = None,
    context: Optional[str] = None,
    check_rc: bool = True,
    suppress_error: bool = False
) -> Optional[str]:
    """
    Backwards-compatible wrapper that safely parses string commands.

    This allows existing code to work while migrating to run_command().
    Uses shlex.split() to safely parse command strings.

    Args:
        cmd: Command string (e.g., "kubectl get pods -o json")
        profile: AWS profile to inject
        context: kubectl context to inject
        check_rc: Raise exception on non-zero return code
        suppress_error: Suppress error logging

    Returns:
        Command stdout as string, or None on failure

    Security Note:
        Uses shlex.split() to safely parse the command string, respecting quotes
        and escapes. Then calls run_command() with shell=False.

    Example:
        run_cmd("kubectl get pods --context mycontext")
        # Internally: ["kubectl", "get", "pods", "--context", "mycontext"]

        run_cmd("kubectl get pod 'my pod name'")
        # Internally: ["kubectl", "get", "pod", "my pod name"]  (quotes handled)
    """
    try:
        # Safe parsing - respects quotes, handles escapes
        parts = shlex.split(cmd)
    except ValueError as e:
        logging.error(f"Failed to parse command: {cmd}. Error: {e}")
        return None

    if not parts:
        logging.error("Empty command")
        return None

    base_command = parts[0]
    args = parts[1:]

    return run_command(base_command, args, profile, context, check_rc, suppress_error)


def _parse_error_message(base_command: str, return_code: int, stderr: str) -> str:
    """
    Parse common error messages for better diagnostics.

    Args:
        base_command: The base command (kubectl, aws)
        return_code: Process return code
        stderr: Standard error output

    Returns:
        Human-readable error message
    """
    stderr_lower = stderr.lower()

    # kubectl-specific errors
    if base_command == "kubectl":
        if "forbidden" in stderr_lower or "unauthorized" in stderr_lower:
            return "Kubernetes RBAC permission denied. Check service account permissions."
        elif "not found" in stderr_lower and "namespace" in stderr_lower:
            return "Kubernetes namespace not found."
        elif "not found" in stderr_lower:
            return "Kubernetes resource not found."
        elif "connection refused" in stderr_lower or "unable to connect" in stderr_lower:
            return "Cannot connect to Kubernetes API server. Check kubeconfig and network connectivity."
        elif "invalid" in stderr_lower and "context" in stderr_lower:
            return "Invalid kubectl context. Check --context argument or kubeconfig."

    # AWS CLI errors
    elif base_command == "aws":
        if "accessdenied" in stderr_lower or "forbidden" in stderr_lower:
            return "AWS IAM permission denied. Check IAM policies and roles."
        elif "notfound" in stderr_lower or "does not exist" in stderr_lower:
            return "AWS resource not found."
        elif "expired" in stderr_lower and "credential" in stderr_lower:
            return "AWS credentials expired. Refresh your credentials."
        elif "invalid" in stderr_lower and "profile" in stderr_lower:
            return "Invalid AWS profile. Check --profile argument or ~/.aws/config."
        elif "no credentials" in stderr_lower or "unable to locate credentials" in stderr_lower:
            return "AWS credentials not found. Configure AWS CLI credentials."
        elif "throttling" in stderr_lower or "rate exceeded" in stderr_lower:
            return "AWS API rate limit exceeded. Command will retry automatically."

    # Generic errors
    if return_code == 1:
        return f"Command failed: {stderr[:200]}"  # Truncate long errors
    elif return_code == 127:
        return f"Command not found or not executable: {base_command}"
    else:
        return f"Command failed with exit code {return_code}: {stderr[:200]}"


def _is_retryable_error(return_code: int, stderr: str) -> bool:
    """
    Determine if an error is transient and should be retried.

    Args:
        return_code: Process return code
        stderr: Standard error output

    Returns:
        True if error is transient and retryable
    """
    stderr_lower = stderr.lower()

    # Retryable patterns (transient errors)
    retryable_patterns = [
        "throttling",
        "rate exceeded",
        "too many requests",
        "connection refused",
        "temporarily unavailable",
        "timeout",
        "timed out",
        "i/o timeout",
        "network is unreachable",
        "service unavailable",
        "internal server error",
        "bad gateway"
    ]

    for pattern in retryable_patterns:
        if pattern in stderr_lower:
            return True

    # Don't retry permission errors, not found errors, etc.
    non_retryable_patterns = [
        "forbidden",
        "unauthorized",
        "accessdenied",
        "permission denied",
        "not found",
        "does not exist",
        "invalid",
        "malformed"
    ]

    for pattern in non_retryable_patterns:
        if pattern in stderr_lower:
            return False

    # Default: don't retry unknown errors
    return False
