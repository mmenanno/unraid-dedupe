#!/usr/bin/env python3
"""
Unraid Deduplication Manager
Core logic for scanning, analyzing, and executing deduplication operations.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional

import yaml

from logging_config import get_logger


# Configure paths from environment variables
DATA_DIR = os.environ.get('DATA_DIR', '/data')
APP_DIR = os.environ.get('APP_DIR', '/app')
CONFIG_DIR = os.path.join(DATA_DIR, 'config')
REPORTS_DIR = os.path.join(DATA_DIR, 'reports')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')


# Configure logging using shared utility
logger = get_logger(__name__)


# Action type constants
ACTION_SAME_DISK = "SAME_DISK"
ACTION_CROSS_DISK = "CROSS_DISK"
ACTION_MANUAL_REVIEW = "MANUAL_REVIEW"
ACTION_PENDING = "PENDING"


@dataclass
class DuplicateFile:
    """Represents a duplicate file"""
    path: str
    size: int
    disk: Optional[str] = None
    priority: int = 999

    def __post_init__(self):
        """Extract disk number from path"""
        self.disk = self._extract_disk()

    def _extract_disk(self) -> Optional[str]:
        """Extract disk identifier from path (e.g., disk1, disk2, cache)"""
        match = re.search(r'/mnt/(disk\d+|cache)/', self.path)
        return match.group(1) if match else None


@dataclass
class DuplicateSet:
    """Represents a set of duplicate files"""
    hash: str
    size: int
    files: List[DuplicateFile]
    keeper: Optional[DuplicateFile] = None
    action: str = ACTION_PENDING

    def analyze(self, path_preferences: List[Dict]) -> None:
        """Determine keeper file and action based on preferences"""
        disks = set(f.disk for f in self.files if f.disk)
        none_disk_count = sum(1 for f in self.files if f.disk is None)

        if none_disk_count == len(self.files):
            self.action = ACTION_SAME_DISK
            self.keeper = self.files[0] if self.files else None
            return

        if len(disks) == 1:
            self.action = ACTION_SAME_DISK
            self.keeper = self.files[0] if self.files else None
            return

        self._apply_preferences(path_preferences)
        sorted_files = sorted(self.files, key=lambda f: (f.priority, f.path))

        if len(sorted_files) >= 2 and sorted_files[0].priority < sorted_files[1].priority:
            self.keeper = sorted_files[0]
            self.action = ACTION_CROSS_DISK
        else:
            self.action = ACTION_MANUAL_REVIEW
            self.keeper = sorted_files[0] if sorted_files else None

    def _apply_preferences(self, path_preferences: List[Dict]) -> None:
        """Apply path preference rules to files"""
        for file in self.files:
            for pref in path_preferences:
                pattern = pref.get('pattern', '')
                priority = pref.get('priority', 999)

                regex_pattern = re.escape(pattern).replace(r'\*', '.*')
                try:
                    if re.match(regex_pattern, file.path):
                        file.priority = min(file.priority, priority)
                        break
                except re.error as e:
                    logger.warning("Invalid pattern '%s': %s", pattern, e)
                    continue


class DedupeConfig:
    """Manages deduplication configuration"""

    def __init__(self, config_path: str = None):
        self.config_path = config_path or os.path.join(CONFIG_DIR, 'dedupe_config.yaml')
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        # If config doesn't exist, copy default
        if not os.path.exists(self.config_path):
            default_path = os.path.join(APP_DIR, 'config', 'dedupe_config.yaml')
            if os.path.exists(default_path):
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                shutil.copy(default_path, self.config_path)
                logger.info("Copied default config to %s", self.config_path)

        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error("Failed to load config: %s", e)
            return self._default_config()

    def _default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'scan_paths': ['/mnt/user/data'],
            'exclude_patterns': ['*.tmp', '*/.Trash-*', '*/System Volume Information/*'],
            'path_preferences': [
                {'pattern': '/mnt/user/data/media/*', 'priority': 1},
                {'pattern': '/mnt/user/data/downloads/*', 'priority': 2}
            ],
            'rmlint_options': {'algorithm': 'xxhash'},
            'safety': {
                'verify_after_hardlink': True,
                'keep_backups': False,
                'cross_disk_action': 'manual_review'
            }
        }

    def save(self, config: Dict) -> None:
        """Save configuration to file atomically"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        temp_path = self.config_path + '.tmp'
        try:
            with open(temp_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            os.replace(temp_path, self.config_path)
            self.config = config
            logger.info("Configuration saved to %s", self.config_path)
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            raise e


class RmlintScanner:
    """Handles rmlint scanning operations"""

    def __init__(self, config: DedupeConfig):
        self.config = config

    def scan(self, output_path: str = None, progress_callback=None) -> bool:
        """Run rmlint scan and save results

        Args:
            output_path: Where to save the JSON output
            progress_callback: Optional callback function(progress: int, message: str) for progress updates

        Returns:
            True if successful, False otherwise
        """
        if output_path is None:
            output_path = os.path.join(REPORTS_DIR, 'scan.json')

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Verify available disk space
        try:
            disk_usage = shutil.disk_usage(os.path.dirname(output_path))
            if disk_usage.free < 100 * 1024 * 1024:
                logger.error("Insufficient disk space for scan output (need 100MB, have %d bytes)", disk_usage.free)
                return False
        except Exception as e:
            logger.warning("Could not check disk space: %s", e)

        scan_paths = self.config.config.get('scan_paths', ['/mnt/user/data'])
        algorithm = self.config.config.get('rmlint_options', {}).get('algorithm', 'xxhash')

        cmd = ['rmlint']
        cmd.extend(scan_paths)

        cmd.extend([
            f'--algorithm={algorithm}',
            f'--output=json:{output_path}',
            '--progress',
            '-vvv'  # Verbose output (can use -v, -vv, or -vvv for increasing verbosity)
        ])

        logger.info("Running rmlint: %s", ' '.join(cmd))
        logger.info("Scanning paths: %s", ', '.join(scan_paths))

        if progress_callback:
            progress_callback(0, "Starting scan...")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            stderr_output = []
            last_output_time = time.time()
            last_heartbeat_time = time.time()
            heartbeat_interval = 30  # Log heartbeat every 30 seconds

            while True:
                line = process.stderr.readline()
                if not line and process.poll() is not None:
                    break

                current_time = time.time()

                # Log heartbeat if no output for a while
                if current_time - last_heartbeat_time >= heartbeat_interval:
                    elapsed = int(current_time - last_output_time)
                    if elapsed >= heartbeat_interval:
                        logger.info("rmlint still running (no output for %d seconds)...", elapsed)
                        if progress_callback:
                            progress_callback(-1, f"Still scanning... (no output for {elapsed}s)")
                    last_heartbeat_time = current_time

                if line:
                    stderr_output.append(line)
                    line_stripped = line.strip()
                    last_output_time = current_time
                    last_heartbeat_time = current_time

                    # Log raw output for debugging
                    logger.debug("rmlint output: %s", line_stripped)

                    if progress_callback:
                        progress_info = self._parse_rmlint_progress(line_stripped)
                        if progress_info:
                            progress_callback(progress_info['percent'], progress_info['message'])

            try:
                return_code = process.wait(timeout=3600)
            except subprocess.TimeoutExpired:
                logger.error("rmlint scan timed out after 1 hour")
                try:
                    process.kill()
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        import signal
                        os.kill(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                    except Exception as e:
                        logger.error("Failed to kill process: %s", e)
                except Exception as e:
                    logger.error("Error during process cleanup: %s", e)
                return False

            if return_code == 0:
                logger.info("rmlint scan completed successfully")
                if progress_callback:
                    progress_callback(100, "Scan complete")
                return True
            else:
                error_output = ''.join(stderr_output)
                logger.error("rmlint scan failed with code %d", return_code)
                logger.error(error_output)
                return False

        except Exception as e:
            logger.error("rmlint scan failed: %s", e)
            return False

    def _parse_rmlint_progress(self, line: str) -> Optional[Dict]:
        """Parse rmlint output to extract progress information

        Returns dict with 'percent' and 'message' keys, or None if no progress info
        """
        # Directory traversal phase
        if "Traversing" in line or "traversing" in line:
            return {'percent': 5, 'message': 'Traversing directory tree...'}

        # Building file tree
        if "Building" in line or "building" in line:
            return {'percent': 8, 'message': 'Building file index...'}

        # Reading/scanning phase
        if "Reading" in line or "reading" in line:
            return {'percent': 12, 'message': 'Reading file metadata...'}

        # File processing with progress numbers
        if "/" in line and "files" in line.lower():
            try:
                match = re.search(r'(\d+)\s*/\s*(\d+)', line)
                if match:
                    current = int(match.group(1))
                    total = int(match.group(2))
                    if total > 0:
                        percent = min(85, int((current / total) * 70) + 15)  # 15-85%
                        return {'percent': percent, 'message': f'Processing files ({current:,}/{total:,})...'}
            except (ValueError, ZeroDivisionError):
                pass

        # File counts without progress
        if "files" in line.lower() and any(word in line.lower() for word in ["found", "processed", "scanning"]):
            try:
                match = re.search(r'(\d+)\s+files?', line)
                if match:
                    file_count = int(match.group(1))
                    return {'percent': 15, 'message': f'Found {file_count:,} files...'}
            except ValueError:
                pass

        # Preprocessing/filtering phase
        if "preprocessing" in line.lower() or "filtering" in line.lower():
            return {'percent': 20, 'message': 'Preprocessing files...'}

        # Size grouping
        if "grouping" in line.lower() or "sorting" in line.lower():
            return {'percent': 25, 'message': 'Grouping files by size...'}

        # Hashing phase (most time-consuming)
        if any(word in line.lower() for word in ["hashing", "hash", "checksum", "checksumming"]):
            # Try to extract percentage from the line itself
            percent_match = re.search(r'(\d+)%', line)
            if percent_match:
                raw_percent = int(percent_match.group(1))
                # Map rmlint's percentage to our 30-80% range
                percent = int(30 + (raw_percent / 100.0 * 50))
                return {'percent': percent, 'message': f'Computing checksums ({raw_percent}%)...'}
            return {'percent': 50, 'message': 'Computing checksums...'}

        # Matching/comparing phase
        if "matching" in line.lower() or "comparing" in line.lower():
            return {'percent': 82, 'message': 'Comparing files for duplicates...'}

        # Finding duplicates
        if "finding" in line.lower() and "duplicate" in line.lower():
            return {'percent': 85, 'message': 'Finding duplicates...'}

        # Writing output
        if "writing" in line.lower() or "output" in line.lower():
            return {'percent': 90, 'message': 'Writing results...'}

        # Final summary
        if "==> In total" in line or "in total" in line.lower():
            return {'percent': 95, 'message': 'Finalizing results...'}

        # Statistics/summary
        if any(word in line.lower() for word in ["duplicates", "duplicate files"]) and any(word in line.lower() for word in ["found", "total"]):
            return {'percent': 97, 'message': 'Generating summary...'}

        return None


class DuplicateParser:
    """Parses rmlint JSON output"""

    def __init__(self, config: DedupeConfig):
        self.config = config

    def _should_exclude(self, file_path: str, exclude_patterns: List[str]) -> bool:
        """Check if file path matches any exclude pattern

        Args:
            file_path: Full path to check
            exclude_patterns: List of glob patterns to match against

        Returns:
            True if file should be excluded, False otherwise
        """
        import fnmatch

        for pattern in exclude_patterns:
            # Convert glob pattern to regex-like matching
            # Support both full path matching and basename matching
            if fnmatch.fnmatch(file_path, pattern):
                return True
            # Also try matching just the basename
            basename = os.path.basename(file_path)
            if fnmatch.fnmatch(basename, pattern):
                return True

        return False

    def parse(self, json_path: str) -> List[DuplicateSet]:
        """Parse rmlint JSON output into DuplicateSet objects"""
        logger.info("Parsing rmlint output: %s", json_path)

        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse JSON output: %s", e)
            return []
        except FileNotFoundError:
            logger.error("JSON output file not found: %s", json_path)
            return []
        except Exception as e:
            logger.error("Unexpected error reading JSON: %s", e)
            return []

        if not isinstance(data, list):
            logger.error("Invalid JSON format: expected list, got %s", type(data))
            return []

        if not data:
            logger.info("No duplicates found - rmlint output is empty")
            return []

        # Get exclude patterns for filtering
        exclude_patterns = self.config.config.get('exclude_patterns', [])

        # Group duplicates by checksum using defaultdict for efficiency
        duplicate_groups: Dict[str, List[Dict]] = defaultdict(list)

        for entry in data:
            if not isinstance(entry, dict):
                logger.warning(f"Skipping invalid entry: {type(entry)}")
                continue
            if entry.get('type') == 'duplicate_file':
                # Apply exclude pattern filtering
                file_path = entry.get('path', '')
                if self._should_exclude(file_path, exclude_patterns):
                    logger.debug(f"Excluding file matching pattern: {file_path}")
                    continue

                checksum = entry.get('checksum', 'unknown')
                duplicate_groups[checksum].append(entry)

        duplicate_sets = []
        path_preferences = self.config.config.get('path_preferences', [])

        for checksum, files in duplicate_groups.items():
            if len(files) < 2:
                continue

            dup_files = [
                DuplicateFile(
                    path=f.get('path', ''),
                    size=f.get('size', 0)
                )
                for f in files
            ]

            dup_set = DuplicateSet(
                hash=checksum,
                size=dup_files[0].size if dup_files else 0,
                files=dup_files
            )

            dup_set.analyze(path_preferences)
            duplicate_sets.append(dup_set)

        logger.info("Found %d duplicate sets", len(duplicate_sets))
        return duplicate_sets


class ReportGenerator:
    """Generates reports from duplicate sets"""

    def generate_json(self, duplicate_sets: List[DuplicateSet], output_path: str) -> None:
        """Generate JSON report for execution"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self._generate_summary(duplicate_sets),
            'duplicate_sets': [self._set_to_dict(ds) for ds in duplicate_sets]
        }

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info("JSON report saved to %s", output_path)

    def generate_markdown(self, duplicate_sets: List[DuplicateSet], output_path: str) -> None:
        """Generate Markdown report for human reading"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        summary = self._generate_summary(duplicate_sets)

        with open(output_path, 'w') as f:
            f.write("# Deduplication Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("## Summary\n\n")
            f.write(f"- **Total Duplicate Sets:** {summary['total_sets']}\n")
            f.write(f"- **Same-Disk Duplicates:** {summary['same_disk_sets']} ({self._format_size(summary['same_disk_space'])} reclaimable)\n")
            f.write(f"- **Cross-Disk Duplicates:** {summary['cross_disk_sets']} ({self._format_size(summary['cross_disk_space'])} reclaimable)\n")
            f.write(f"- **Manual Review Needed:** {summary['manual_review_sets']}\n")
            f.write(f"- **Total Space Reclaimable:** {self._format_size(summary['total_reclaimable'])}\n\n")

            self._write_category(f, duplicate_sets, ACTION_SAME_DISK, "Same-Disk Duplicates")
            self._write_category(f, duplicate_sets, ACTION_CROSS_DISK, "Cross-Disk Duplicates")
            self._write_category(f, duplicate_sets, ACTION_MANUAL_REVIEW, "Manual Review Required")

        logger.info("Markdown report saved to %s", output_path)

    def _write_category(self, f, duplicate_sets: List[DuplicateSet], action: str, title: str) -> None:
        """Write a category section to markdown file"""
        category_sets = [ds for ds in duplicate_sets if ds.action == action]
        if not category_sets:
            return

        f.write(f"## {title}\n\n")

        for ds in category_sets[:20]:  # Limit to first 20 for readability
            f.write(f"### Set {ds.hash[:8]}... ({self._format_size(ds.size)})\n\n")
            f.write(f"**Keeper:** `{ds.keeper.path if ds.keeper else 'N/A'}`\n\n")
            f.write("**Duplicates:**\n")
            for file in ds.files:
                if ds.keeper and file.path == ds.keeper.path:
                    continue
                f.write(f"- `{file.path}` (disk: {file.disk or 'unknown'})\n")
            f.write("\n")

        if len(category_sets) > 20:
            f.write(f"*... and {len(category_sets) - 20} more sets*\n\n")

    def _generate_summary(self, duplicate_sets: List[DuplicateSet]) -> Dict:
        """Generate summary statistics"""
        summary = {
            'total_sets': len(duplicate_sets),
            'same_disk_sets': 0,
            'same_disk_space': 0,
            'cross_disk_sets': 0,
            'cross_disk_space': 0,
            'manual_review_sets': 0,
            'total_reclaimable': 0
        }

        for ds in duplicate_sets:
            space = ds.size * (len(ds.files) - 1)

            if ds.action == ACTION_SAME_DISK:
                summary['same_disk_sets'] += 1
                summary['same_disk_space'] += space
            elif ds.action == ACTION_CROSS_DISK:
                summary['cross_disk_sets'] += 1
                summary['cross_disk_space'] += space
            elif ds.action == ACTION_MANUAL_REVIEW:
                summary['manual_review_sets'] += 1

            summary['total_reclaimable'] += space

        return summary

    def _set_to_dict(self, ds: DuplicateSet) -> Dict:
        """Convert DuplicateSet to dictionary"""
        return {
            'hash': ds.hash,
            'size': ds.size,
            'action': ds.action,
            'keeper': asdict(ds.keeper) if ds.keeper else None,
            'files': [asdict(f) for f in ds.files]
        }

    def _format_size(self, size_bytes: int) -> str:
        """Format size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"


class DedupeExecutor:
    """Executes deduplication operations"""

    def __init__(self, config: DedupeConfig):
        self.config = config
        self.log_path = os.path.join(LOGS_DIR, 'execution.log')
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def _get_safety_config(self, key: str, default=None):
        """Helper method to get safety configuration value"""
        return self.config.config.get('safety', {}).get(key, default)

    def execute(self, report_path: str) -> Dict:
        """Execute deduplication from report"""
        logger.info("Executing deduplication from %s", report_path)

        with open(report_path, 'r') as f:
            report = json.load(f)

        stats = {
            'processed': 0,
            'succeeded': 0,
            'failed': 0,
            'skipped': 0,
            'space_freed': 0
        }

        for ds_dict in report['duplicate_sets']:
            action = ds_dict.get('action')

            if action == ACTION_MANUAL_REVIEW:
                stats['skipped'] += 1
                continue

            if action == ACTION_SAME_DISK:
                result = self._execute_same_disk(ds_dict)
            elif action == ACTION_CROSS_DISK:
                result = self._execute_cross_disk(ds_dict)
            else:
                stats['skipped'] += 1
                continue

            stats['processed'] += 1
            if result:
                stats['succeeded'] += 1
                stats['space_freed'] += ds_dict['size'] * (len(ds_dict['files']) - 1)
            else:
                stats['failed'] += 1

        logger.info("Execution complete: %s", stats)
        return stats

    def _execute_same_disk(self, ds_dict: Dict) -> bool:
        """Execute same-disk deduplication (simple hardlink)"""
        keeper = ds_dict['keeper']
        if not keeper:
            return False

        keeper_path = keeper['path']

        try:
            keeper_stat = os.stat(keeper_path)
            for file in ds_dict['files']:
                if file['path'] == keeper_path:
                    continue
                file_stat = os.stat(file['path'])
                if keeper_stat.st_dev != file_stat.st_dev:
                    logger.error("Files not on same device: %s (dev %d) vs %s (dev %d)",
                                keeper_path, keeper_stat.st_dev, file['path'], file_stat.st_dev)
                    return False
        except FileNotFoundError as e:
            logger.error("File not found during device check: %s", e)
            return False
        except Exception as e:
            logger.error("Failed to check device: %s", e)
            return False

        for file in ds_dict['files']:
            if file['path'] == keeper_path:
                continue

            try:
                if not self._create_hardlink(keeper_path, file['path']):
                    return False
            except Exception as e:
                logger.error("Failed to dedupe %s: %s", file['path'], e)
                return False

        return True

    def _execute_cross_disk(self, ds_dict: Dict) -> bool:
        """Execute cross-disk deduplication based on configured action

        Note: Hardlinks don't work across different disks/filesystems.
        Options:
        - skip: Don't process cross-disk duplicates (safest)
        - delete_duplicate: Delete non-preferred duplicates (saves space, loses redundancy)
        - manual_review: Skip and log for manual review
        """
        keeper = ds_dict['keeper']
        if not keeper:
            return False

        keeper_path = keeper['path']
        cross_disk_action = self._get_safety_config('cross_disk_action', 'manual_review')

        if not os.path.exists(keeper_path):
            logger.error("Keeper file does not exist: %s", keeper_path)
            return False

        if cross_disk_action == 'skip':
            logger.info("Skipping cross-disk duplicate set (keeper: %s)", keeper_path)
            return True

        for file in ds_dict['files']:
            file_path = file['path']
            if file_path == keeper_path:
                continue

            try:
                if not os.path.exists(file_path):
                    logger.warning("File does not exist, skipping: %s", file_path)
                    continue

                if cross_disk_action == 'manual_review':
                    logger.info("Cross-disk duplicate marked for manual review: %s", file_path)
                    continue

                elif cross_disk_action == 'delete_duplicate':
                    keeper_stat = os.stat(keeper_path)
                    dup_stat = os.stat(file_path)

                    if keeper_stat.st_dev == dup_stat.st_dev:
                        logger.info("Files on same device, using hardlink: %s", file_path)
                        if not self._create_hardlink(keeper_path, file_path):
                            return False
                    else:
                        logger.warning("Deleting cross-disk duplicate: %s", file_path)

                        try:
                            with open(keeper_path, 'rb') as keeper_f, open(file_path, 'rb') as dup_f:
                                keeper_fstat = os.fstat(keeper_f.fileno())
                                dup_fstat = os.fstat(dup_f.fileno())

                                if keeper_fstat.st_size != dup_fstat.st_size:
                                    logger.error("Size mismatch! Keeper: %d, Duplicate: %d",
                                               keeper_fstat.st_size, dup_fstat.st_size)
                                    return False

                                if keeper_fstat.st_mtime != keeper_stat.st_mtime:
                                    logger.error("Keeper file was modified during operation: %s", keeper_path)
                                    return False
                                if dup_fstat.st_mtime != dup_stat.st_mtime:
                                    logger.error("Duplicate file was modified during operation: %s", file_path)
                                    return False

                        except Exception as e:
                            logger.error("Failed to verify files before deletion: %s", e)
                            return False

                        if self._get_safety_config('keep_backups', False):
                            try:
                                disk_usage = shutil.disk_usage(os.path.dirname(file_path))
                                if disk_usage.free < dup_stat.st_size * 1.1:
                                    logger.error("Insufficient disk space for backup (need %d bytes, have %d bytes)",
                                               dup_stat.st_size, disk_usage.free)
                                    return False
                            except Exception as e:
                                logger.warning("Could not check disk space for backup: %s", e)

                            shutil.copy2(file_path, f"{file_path}.backup")
                            logger.info("Created backup: %s.backup", file_path)

                        os.remove(file_path)
                        logger.info("Deleted cross-disk duplicate: %s", file_path)
                else:
                    logger.error("Unknown cross_disk_action: %s", cross_disk_action)
                    return False

            except Exception as e:
                logger.error("Failed to process cross-disk duplicate %s: %s", file_path, e)
                return False

        return True

    def _create_hardlink(self, source: str, duplicate: str) -> bool:
        """Create hardlink and verify

        Uses atomic operation: create temp hardlink first, then replace original
        to prevent data loss if hardlink creation fails.
        """
        if not os.path.exists(source):
            logger.error("Source file does not exist: %s", source)
            return False
        if not os.path.exists(duplicate):
            logger.error("Duplicate file does not exist: %s", duplicate)
            return False

        verify = self._get_safety_config('verify_after_hardlink', True)

        source_stat = os.stat(source)
        source_inode = source_stat.st_ino

        if self._get_safety_config('keep_backups', False):
            shutil.copy2(duplicate, f"{duplicate}.backup")

        temp_link = f"{duplicate}.hardlink_temp"
        try:
            os.link(source, temp_link)

            if verify:
                temp_stat = os.stat(temp_link)
                if temp_stat.st_ino != source_inode:
                    logger.error("Hardlink verification failed for temp file: %s", temp_link)
                    os.remove(temp_link)
                    return False

            os.replace(temp_link, duplicate)

        except Exception as e:
            logger.error("Failed to create hardlink: %s", e)
            if os.path.exists(temp_link):
                try:
                    os.remove(temp_link)
                except Exception as cleanup_error:
                    logger.warning("Failed to cleanup temp file %s: %s", temp_link, cleanup_error)
            return False

        logger.info("Successfully hardlinked: %s -> %s", duplicate, source)
        return True


class DedupeManager:
    """Main manager class"""

    def __init__(self, config_path: str = None):
        self.config = DedupeConfig(config_path)
        self.scanner = RmlintScanner(self.config)
        self.parser = DuplicateParser(self.config)
        self.report_gen = ReportGenerator()
        self.executor = DedupeExecutor(self.config)

    def reload_config(self) -> None:
        """Reload configuration from disk

        This ensures all components use the updated configuration
        after it's been modified via the web UI or CLI.
        """
        self.config.config = self.config._load_config()
        logger.info("Configuration reloaded")

    def scan(self, report_id: Optional[str] = None, progress_callback=None) -> str:
        """Run complete scan and generate reports

        Args:
            report_id: Optional custom report ID
            progress_callback: Optional callback(progress: int, message: str) for progress updates

        Returns:
            Report ID string
        """
        if not report_id:
            report_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        report_dir = os.path.join(REPORTS_DIR, report_id)
        os.makedirs(report_dir, exist_ok=True)

        scan_json = os.path.join(report_dir, 'scan.json')
        report_json = os.path.join(report_dir, 'report.json')
        report_md = os.path.join(report_dir, 'report.md')

        if not self.scanner.scan(scan_json, progress_callback=progress_callback):
            raise Exception("Scan failed")

        if progress_callback:
            progress_callback(92, "Parsing results...")
        duplicate_sets = self.parser.parse(scan_json)

        if progress_callback:
            progress_callback(95, "Generating reports...")
        self.report_gen.generate_json(duplicate_sets, report_json)
        self.report_gen.generate_markdown(duplicate_sets, report_md)

        if progress_callback:
            progress_callback(100, "Complete")

        logger.info("Scan complete. Report ID: %s", report_id)
        return report_id

    def execute_report(self, report_id: str) -> Dict:
        """Execute deduplication from report"""
        report_json = os.path.join(REPORTS_DIR, report_id, 'report.json')

        if not os.path.exists(report_json):
            raise FileNotFoundError(f"Report not found: {report_json}")

        return self.executor.execute(report_json)

    def list_reports(self) -> List[Dict]:
        """List all available reports"""
        if not os.path.exists(REPORTS_DIR):
            return []

        reports = []
        try:
            report_ids = os.listdir(REPORTS_DIR)
        except PermissionError as e:
            logger.error("Permission denied accessing reports directory: %s", e)
            return []
        except Exception as e:
            logger.error("Error listing reports directory: %s", e)
            return []

        for report_id in report_ids:
            report_path = os.path.join(REPORTS_DIR, report_id, 'report.json')
            if os.path.exists(report_path):
                try:
                    with open(report_path, 'r') as f:
                        data = json.load(f)
                        reports.append({
                            'id': report_id,
                            'generated_at': data.get('generated_at'),
                            'summary': data.get('summary')
                        })
                except json.JSONDecodeError as e:
                    logger.warning("Skipping report with invalid JSON %s: %s", report_id, e)
                    continue
                except (FileNotFoundError, PermissionError) as e:
                    logger.warning("Skipping inaccessible report %s: %s", report_id, e)
                    continue
                except Exception as e:
                    logger.warning("Skipping report %s due to unexpected error: %s", report_id, e)
                    continue

        return sorted(reports, key=lambda r: r.get('generated_at') or '', reverse=True)

    def get_report(self, report_id: str) -> Optional[Dict]:
        """Get specific report details"""
        report_json = os.path.join(REPORTS_DIR, report_id, 'report.json')

        if not os.path.exists(report_json):
            return None

        with open(report_json, 'r') as f:
            return json.load(f)


def main():
    """CLI interface"""
    if len(sys.argv) < 2:
        print("Usage: python dedupe_manager.py <command> [args]")
        print("Commands:")
        print("  scan                 - Run scan and generate report")
        print("  report <id>          - View report")
        print("  execute <id>         - Execute report")
        print("  list                 - List all reports")
        sys.exit(1)

    command = sys.argv[1]
    manager = DedupeManager()

    if command == "scan":
        report_id = manager.scan()
        print(f"Scan complete. Report ID: {report_id}")

    elif command == "report":
        if len(sys.argv) < 3:
            print("Usage: python dedupe_manager.py report <id>")
            sys.exit(1)
        report_id = sys.argv[2]
        report = manager.get_report(report_id)
        if report:
            print(json.dumps(report, indent=2))
        else:
            print(f"Report not found: {report_id}")

    elif command == "execute":
        if len(sys.argv) < 3:
            print("Usage: python dedupe_manager.py execute <id>")
            sys.exit(1)
        report_id = sys.argv[2]
        stats = manager.execute_report(report_id)
        print(f"Execution complete: {json.dumps(stats, indent=2)}")

    elif command == "list":
        reports = manager.list_reports()
        for report in reports:
            print(f"{report['id']}: {report['generated_at']}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

