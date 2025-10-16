#!/usr/bin/env python3
"""
Scheduler for automated deduplication scans
Uses APScheduler for cron-based scheduling
"""

import json
import logging
import os
from datetime import datetime
from typing import Optional, Dict, Callable

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger


# Configure paths from environment variables
DATA_DIR = os.environ.get('DATA_DIR', '/data')
CONFIG_DIR = os.path.join(DATA_DIR, 'config')

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Manages scheduled deduplication scans"""

    def __init__(self, scan_callback: Callable[[], None]):
        """
        Initialize scheduler

        Args:
            scan_callback: Function to call when scan is triggered
        """
        self.scheduler = BackgroundScheduler()
        self.scan_callback = scan_callback
        self.config_path = os.path.join(CONFIG_DIR, 'schedule.json')
        self.job_id = "dedupe_scan"

        # Load configuration
        self.config = self._load_config()

        # Start scheduler
        self.scheduler.start()
        logger.info("Scheduler initialized")

        # Apply current schedule if enabled
        if self.config.get('enabled', False):
            self._apply_schedule()

    def _load_config(self) -> Dict:
        """Load schedule configuration from file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load schedule config: {e}")

        # Return default config (disabled)
        return {
            'enabled': False,
            'cron': '0 2 * * 0',  # Weekly at 2 AM on Sunday
            'description': 'Weekly scan'
        }

    def _save_config(self) -> None:
        """Save schedule configuration to file"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        logger.info("Schedule configuration saved")

    def _apply_schedule(self) -> None:
        """Apply current schedule to scheduler"""
        # Remove existing job if any
        if self.scheduler.get_job(self.job_id):
            self.scheduler.remove_job(self.job_id)

        if not self.config.get('enabled', False):
            logger.info("Scheduled scans disabled")
            return

        cron_expr = self.config.get('cron', '0 2 * * 0')

        try:
            # Parse cron expression
            parts = cron_expr.split()
            if len(parts) != 5:
                raise ValueError("Invalid cron expression: must have 5 fields (minute hour day month day_of_week)")

            minute, hour, day, month, day_of_week = parts

            def validate_field(value: str, name: str, min_val: int, max_val: int) -> None:
                """Basic validation for cron field values"""
                if value == '*' or value.startswith('*/'):
                    return
                if value.isdigit():
                    num = int(value)
                    if num < min_val or num > max_val:
                        raise ValueError(f"{name} must be between {min_val} and {max_val}, got {num}")

            try:
                validate_field(minute, "minute", 0, 59)
                validate_field(hour, "hour", 0, 23)
                validate_field(day, "day", 1, 31)
                validate_field(month, "month", 1, 12)
                validate_field(day_of_week, "day_of_week", 0, 6)
            except ValueError as e:
                logger.error("Cron validation error: %s", e)
                raise

            # Create trigger
            trigger = CronTrigger(
                minute=minute,
                hour=hour,
                day=day,
                month=month,
                day_of_week=day_of_week
            )

            # Add job
            self.scheduler.add_job(
                self.scan_callback,
                trigger=trigger,
                id=self.job_id,
                name="Deduplication Scan",
                replace_existing=True
            )

            logger.info("Scheduled scan: %s", cron_expr)

            # Log next run time
            job = self.scheduler.get_job(self.job_id)
            if job:
                logger.info("Next scheduled run: %s", job.next_run_time)

        except ValueError as e:
            logger.error("Invalid cron expression '%s': %s", cron_expr, e)
        except Exception as e:
            logger.error("Failed to apply schedule: %s", e)

    def get_config(self) -> Dict:
        """Get current schedule configuration"""
        config = self.config.copy()

        # Add next run time if job exists
        job = self.scheduler.get_job(self.job_id)
        if job:
            config['next_run'] = job.next_run_time.isoformat() if job.next_run_time else None
        else:
            config['next_run'] = None

        return config

    def update_config(self, enabled: bool, cron: str, description: str = "") -> bool:
        """
        Update schedule configuration

        Args:
            enabled: Whether scheduling is enabled
            cron: Cron expression (e.g., "0 2 * * 0")
            description: Human-readable description

        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate cron expression
            parts = cron.split()
            if len(parts) != 5:
                raise ValueError("Invalid cron expression format")

            # Update config
            self.config = {
                'enabled': enabled,
                'cron': cron,
                'description': description or self._describe_cron(cron),
                'updated_at': datetime.now().isoformat()
            }

            # Save to file
            self._save_config()

            # Apply to scheduler
            self._apply_schedule()

            return True

        except Exception as e:
            logger.error(f"Failed to update schedule: {e}")
            return False

    def enable(self) -> bool:
        """Enable scheduled scans"""
        self.config['enabled'] = True
        self._save_config()
        self._apply_schedule()
        return True

    def disable(self) -> bool:
        """Disable scheduled scans"""
        self.config['enabled'] = False
        self._save_config()
        self._apply_schedule()
        return True

    def trigger_now(self) -> None:
        """Manually trigger a scan now"""
        logger.info("Manually triggering scan")
        self.scan_callback()

    def _describe_cron(self, cron: str) -> str:
        """Generate human-readable description of cron expression"""
        try:
            parts = cron.split()
            minute, hour, day, month, day_of_week = parts

            if cron == "0 2 * * 0":
                return "Weekly on Sunday at 2:00 AM"
            elif cron == "0 2 * * *":
                return "Daily at 2:00 AM"
            elif cron == "0 0 1 * *":
                return "Monthly on the 1st at midnight"
            elif cron == "0 */6 * * *":
                return "Every 6 hours"
            else:
                return f"Custom schedule: {cron}"
        except Exception:
            return cron

    def get_next_run_time(self) -> Optional[datetime]:
        """Get next scheduled run time"""
        job = self.scheduler.get_job(self.job_id)
        if job and job.next_run_time:
            return job.next_run_time
        return None

    def shutdown(self) -> None:
        """Shutdown scheduler"""
        self.scheduler.shutdown()
        logger.info("Scheduler shut down")


def get_cron_presets() -> Dict[str, str]:
    """Get common cron expression presets"""
    return {
        'Daily at 2 AM': '0 2 * * *',
        'Weekly (Sunday 2 AM)': '0 2 * * 0',
        'Weekly (Monday 2 AM)': '0 2 * * 1',
        'Monthly (1st at 2 AM)': '0 2 1 * *',
        'Every 6 hours': '0 */6 * * *',
        'Every 12 hours': '0 */12 * * *'
    }

