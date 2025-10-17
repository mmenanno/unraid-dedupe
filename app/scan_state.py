#!/usr/bin/env python3
"""
Shared scan state manager using file-based storage
This allows scan state to persist across Gunicorn worker processes
"""

import json
import logging
import os
import threading
import time
from datetime import datetime
from typing import Optional, Dict, Any
from filelock import FileLock

from logging_config import get_logger


# Configure logging using shared utility
logger = get_logger(__name__)


class SharedScanState:
    """
    File-based scan state that can be shared across multiple processes.
    Uses file locking to ensure thread and process safety.
    """

    def __init__(self, state_file: str):
        """
        Initialize shared state manager

        Args:
            state_file: Path to the JSON file storing scan state
        """
        self.state_file = state_file
        self.lock_file = state_file + '.lock'

        # Ensure directory exists
        os.makedirs(os.path.dirname(state_file), exist_ok=True)

        # Initialize state file if it doesn't exist
        if not os.path.exists(self.state_file):
            self._write_state(self._get_default_state())
        else:
            # Check for stale state on startup (process was killed by restart)
            self._clean_stale_state_on_startup()

    def _get_default_state(self) -> Dict[str, Any]:
        """Get default initial state"""
        return {
            'running': False,
            'progress': 0,
            'message': 'Idle',
            'report_id': None,
            'cancel_requested': False,
            'started_at': None,
            'updated_at': None,
            'process_pid': None
        }

    def _clean_stale_state_on_startup(self) -> None:
        """
        Clean up stale state on app startup.
        If a scan was running before restart, the process is now dead.
        """
        lock = FileLock(self.lock_file, timeout=10)
        try:
            with lock:
                if not os.path.exists(self.state_file):
                    return

                with open(self.state_file, 'r') as f:
                    state = json.load(f)

                # Check if state indicates a scan is running
                if not state.get('running'):
                    return

                process_pid = state.get('process_pid')

                # Check if the process actually exists
                process_exists = False
                if process_pid:
                    try:
                        # Send signal 0 to check if process exists (doesn't actually send a signal)
                        os.kill(process_pid, 0)
                        process_exists = True
                    except (ProcessLookupError, PermissionError):
                        process_exists = False

                if not process_exists:
                    # Process is dead but state shows running - clear stale state
                    logger.warning(
                        f"Detected stale scan state on startup (PID {process_pid} not running). "
                        "Clearing state. This is normal after an app restart."
                    )
                    state = self._get_default_state()
                    state['message'] = 'Ready (cleared stale state from previous run)'
                    self._write_state_unlocked(state)
                else:
                    logger.info(f"Scan process PID {process_pid} is still running (unlikely after restart)")

        except Exception as e:
            logger.error(f"Failed to clean stale state on startup: {e}")

    def _read_state(self) -> Dict[str, Any]:
        """
        Read state from file with locking

        Returns:
            Current state dictionary
        """
        lock = FileLock(self.lock_file, timeout=10)
        try:
            with lock:
                if not os.path.exists(self.state_file):
                    return self._get_default_state()

                with open(self.state_file, 'r') as f:
                    state = json.load(f)

                # Check for stale state (running for more than 24 hours without update)
                # Large scans can take many hours, so we use a generous timeout
                if state.get('running'):
                    updated_at = state.get('updated_at')
                    if updated_at:
                        try:
                            updated_time = datetime.fromisoformat(updated_at)
                            age_seconds = (datetime.now() - updated_time).total_seconds()
                            if age_seconds > 86400:  # 24 hours
                                logger.warning(f"Detected stale scan state (age: {age_seconds}s), resetting")
                                state = self._get_default_state()
                                self._write_state_unlocked(state)
                        except (ValueError, TypeError):
                            pass

                return state
        except Exception as e:
            logger.error(f"Failed to read scan state: {e}")
            return self._get_default_state()

    def _write_state_unlocked(self, state: Dict[str, Any]) -> None:
        """Write state without acquiring lock (assumes lock is already held)"""
        state['updated_at'] = datetime.now().isoformat()

        # Write to temp file first, then atomic rename
        temp_file = self.state_file + '.tmp'
        with open(temp_file, 'w') as f:
            json.dump(state, f, indent=2)
        os.replace(temp_file, self.state_file)

    def _write_state(self, state: Dict[str, Any]) -> None:
        """
        Write state to file with locking

        Args:
            state: State dictionary to write
        """
        lock = FileLock(self.lock_file, timeout=10)
        try:
            with lock:
                self._write_state_unlocked(state)
        except Exception as e:
            logger.error(f"Failed to write scan state: {e}")

    def get_state(self) -> Dict[str, Any]:
        """
        Get current scan state

        Returns:
            Dictionary containing all state fields
        """
        return self._read_state()

    def set_running(self, running: bool) -> None:
        """Set running state"""
        state = self._read_state()
        state['running'] = running
        if running:
            state['started_at'] = datetime.now().isoformat()
        self._write_state(state)

    def set_progress(self, progress: int, message: str) -> None:
        """Set progress and message"""
        state = self._read_state()
        state['progress'] = progress
        state['message'] = message
        self._write_state(state)

    def set_report_id(self, report_id: str) -> None:
        """Set report ID"""
        state = self._read_state()
        state['report_id'] = report_id
        self._write_state(state)

    def set_process_pid(self, pid: Optional[int]) -> None:
        """Set the PID of the running scan process"""
        state = self._read_state()
        state['process_pid'] = pid
        self._write_state(state)
        if pid:
            logger.info(f"Scan process PID set to {pid}")

    def get_process_pid(self) -> Optional[int]:
        """Get the PID of the running scan process"""
        state = self._read_state()
        return state.get('process_pid')

    def request_cancel(self) -> None:
        """Request scan cancellation and signal the process if running"""
        import signal

        state = self._read_state()
        state['cancel_requested'] = True
        process_pid = state.get('process_pid')
        self._write_state(state)

        logger.info("Scan cancellation requested")

        # If we have a process PID, send SIGTERM directly for immediate cancellation
        if process_pid:
            try:
                logger.info(f"Sending SIGTERM to scan process PID {process_pid}")
                os.kill(process_pid, signal.SIGTERM)
                logger.info(f"Successfully sent SIGTERM to PID {process_pid}")
            except ProcessLookupError:
                logger.warning(f"Process {process_pid} not found (may have already exited)")
            except PermissionError:
                logger.error(f"Permission denied to signal process {process_pid}")
            except Exception as e:
                logger.error(f"Failed to signal process {process_pid}: {e}")

    def is_cancel_requested(self) -> bool:
        """Check if cancellation has been requested"""
        state = self._read_state()
        return state.get('cancel_requested', False)

    def is_running(self) -> bool:
        """Check if scan is currently running"""
        state = self._read_state()
        return state.get('running', False)

    def reset(self) -> None:
        """Reset to initial state"""
        self._write_state(self._get_default_state())

    def to_dict(self) -> Dict[str, Any]:
        """Get state as dictionary (for JSON responses)"""
        return self._read_state()

    def acquire_scan_lock(self) -> bool:
        """
        Try to acquire the scan lock (start a new scan)

        Returns:
            True if lock was acquired, False if scan already running
        """
        lock = FileLock(self.lock_file, timeout=10)
        try:
            with lock:
                # Read state directly without calling _read_state to avoid recursive locking
                if not os.path.exists(self.state_file):
                    state = self._get_default_state()
                else:
                    with open(self.state_file, 'r') as f:
                        state = json.load(f)

                if state.get('running', False):
                    return False

                # Acquire lock by setting running=True
                state['running'] = True
                state['cancel_requested'] = False
                state['progress'] = 0
                state['message'] = 'Starting scan...'
                state['report_id'] = None
                state['started_at'] = datetime.now().isoformat()
                self._write_state_unlocked(state)
                return True
        except Exception as e:
            logger.error(f"Failed to acquire scan lock: {e}")
            return False

    def release_scan_lock(self) -> None:
        """Release the scan lock (scan completed or failed)"""
        state = self._read_state()
        state['running'] = False
        state['process_pid'] = None  # Clear the PID
        self._write_state(state)
        logger.info("Scan lock released (scan ended)")

