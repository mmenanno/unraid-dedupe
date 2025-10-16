#!/usr/bin/env python3
"""
Unraid Deduplication Manager
Core logic for scanning, analyzing, and executing deduplication operations.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import logging

import yaml


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


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
    action: str = "PENDING"  # SAME_DISK, CROSS_DISK, MANUAL_REVIEW

    def analyze(self, path_preferences: List[Dict]) -> None:
        """Determine keeper file and action based on preferences"""
        # Check if all files are on same disk
        disks = set(f.disk for f in self.files if f.disk)

        if len(disks) == 1:
            self.action = "SAME_DISK"
            # For same-disk, just pick first file as keeper
            self.keeper = self.files[0]
            return

        # Cross-disk duplicates - apply path preferences
        self._apply_preferences(path_preferences)

        # Find keeper based on priority
        sorted_files = sorted(self.files, key=lambda f: (f.priority, f.path))

        # Check if there's a clear winner
        if sorted_files[0].priority < sorted_files[1].priority:
            self.keeper = sorted_files[0]
            self.action = "CROSS_DISK"
        else:
            # Tie or no clear preference
            self.action = "MANUAL_REVIEW"
            self.keeper = sorted_files[0]  # Still set a default keeper

    def _apply_preferences(self, path_preferences: List[Dict]) -> None:
        """Apply path preference rules to files"""
        for file in self.files:
            for pref in path_preferences:
                pattern = pref.get('pattern', '')
                priority = pref.get('priority', 999)

                # Convert glob pattern to regex
                regex_pattern = pattern.replace('*', '.*')
                if re.match(regex_pattern, file.path):
                    file.priority = min(file.priority, priority)
                    break


class DedupeConfig:
    """Manages deduplication configuration"""

    def __init__(self, config_path: str = "/data/config/dedupe_config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        # If config doesn't exist, copy default
        if not os.path.exists(self.config_path):
            default_path = "/app/config/dedupe_config.yaml"
            if os.path.exists(default_path):
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                shutil.copy(default_path, self.config_path)
                logger.info(f"Copied default config to {self.config_path}")

        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
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
        """Save configuration to file"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        self.config = config
        logger.info(f"Configuration saved to {self.config_path}")


class RmlintScanner:
    """Handles rmlint scanning operations"""

    def __init__(self, config: DedupeConfig):
        self.config = config

    def scan(self, output_path: str = "/data/reports/scan.json") -> bool:
        """Run rmlint scan and save results"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        scan_paths = self.config.config.get('scan_paths', ['/mnt/user/data'])
        algorithm = self.config.config.get('rmlint_options', {}).get('algorithm', 'xxhash')

        # Build rmlint command
        cmd = ['rmlint']

        # Add scan paths
        cmd.extend(scan_paths)

        # Add exclude patterns
        for pattern in self.config.config.get('exclude_patterns', []):
            cmd.extend(['--exclude', pattern])

        # Add options
        cmd.extend([
            f'--algorithm={algorithm}',
            f'--output=json:{output_path}',
            '--progress',
            '--no-hidden'
        ])

        logger.info(f"Running rmlint: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info("rmlint scan completed successfully")
            logger.debug(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"rmlint scan failed: {e}")
            logger.error(e.stderr)
            return False


class DuplicateParser:
    """Parses rmlint JSON output"""

    def __init__(self, config: DedupeConfig):
        self.config = config

    def parse(self, json_path: str) -> List[DuplicateSet]:
        """Parse rmlint JSON output into DuplicateSet objects"""
        logger.info(f"Parsing rmlint output: {json_path}")

        with open(json_path, 'r') as f:
            data = json.load(f)

        # Group duplicates by checksum
        duplicate_groups: Dict[str, List[Dict]] = {}

        for entry in data:
            if entry.get('type') == 'duplicate_file':
                checksum = entry.get('checksum', 'unknown')
                if checksum not in duplicate_groups:
                    duplicate_groups[checksum] = []
                duplicate_groups[checksum].append(entry)

        # Create DuplicateSet objects
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

        logger.info(f"Found {len(duplicate_sets)} duplicate sets")
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

        logger.info(f"JSON report saved to {output_path}")

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

            # Same-disk duplicates
            self._write_category(f, duplicate_sets, "SAME_DISK", "Same-Disk Duplicates")

            # Cross-disk duplicates
            self._write_category(f, duplicate_sets, "CROSS_DISK", "Cross-Disk Duplicates")

            # Manual review
            self._write_category(f, duplicate_sets, "MANUAL_REVIEW", "Manual Review Required")

        logger.info(f"Markdown report saved to {output_path}")

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
            # Calculate space per set (all duplicates except keeper)
            space = ds.size * (len(ds.files) - 1)

            if ds.action == "SAME_DISK":
                summary['same_disk_sets'] += 1
                summary['same_disk_space'] += space
            elif ds.action == "CROSS_DISK":
                summary['cross_disk_sets'] += 1
                summary['cross_disk_space'] += space
            elif ds.action == "MANUAL_REVIEW":
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
        self.log_path = "/data/logs/execution.log"
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def execute(self, report_path: str) -> Dict:
        """Execute deduplication from report"""
        logger.info(f"Executing deduplication from {report_path}")

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

            if action == 'MANUAL_REVIEW':
                stats['skipped'] += 1
                continue

            if action == 'SAME_DISK':
                result = self._execute_same_disk(ds_dict)
            elif action == 'CROSS_DISK':
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

        logger.info(f"Execution complete: {stats}")
        return stats

    def _execute_same_disk(self, ds_dict: Dict) -> bool:
        """Execute same-disk deduplication (simple hardlink)"""
        keeper = ds_dict['keeper']
        if not keeper:
            return False

        keeper_path = keeper['path']

        for file in ds_dict['files']:
            if file['path'] == keeper_path:
                continue

            try:
                if not self._create_hardlink(keeper_path, file['path']):
                    return False
            except Exception as e:
                logger.error(f"Failed to dedupe {file['path']}: {e}")
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
        cross_disk_action = self.config.config.get('safety', {}).get('cross_disk_action', 'manual_review')

        if cross_disk_action == 'skip':
            logger.info(f"Skipping cross-disk duplicate set (keeper: {keeper_path})")
            return True

        for file in ds_dict['files']:
            file_path = file['path']
            if file_path == keeper_path:
                continue

            try:
                if cross_disk_action == 'manual_review':
                    logger.info(f"Cross-disk duplicate marked for manual review: {file_path}")
                    continue

                elif cross_disk_action == 'delete_duplicate':
                    # Verify files are actually on different disks
                    keeper_stat = os.stat(keeper_path)
                    dup_stat = os.stat(file_path)

                    if keeper_stat.st_dev == dup_stat.st_dev:
                        # Actually on same disk - can use hardlink instead
                        logger.info(f"Files on same device, using hardlink: {file_path}")
                        if not self._create_hardlink(keeper_path, file_path):
                            return False
                    else:
                        # Different disks - delete duplicate after verification
                        logger.warning(f"Deleting cross-disk duplicate: {file_path}")

                        # Verify file sizes match as safety check
                        if keeper_stat.st_size != dup_stat.st_size:
                            logger.error(f"Size mismatch! Keeper: {keeper_stat.st_size}, Duplicate: {dup_stat.st_size}")
                            return False

                        # Create backup if configured
                        if self.config.config.get('safety', {}).get('keep_backups', False):
                            shutil.copy2(file_path, f"{file_path}.backup")
                            logger.info(f"Created backup: {file_path}.backup")

                        # Delete the duplicate
                        os.remove(file_path)
                        logger.info(f"Deleted cross-disk duplicate: {file_path}")
                else:
                    logger.error(f"Unknown cross_disk_action: {cross_disk_action}")
                    return False

            except Exception as e:
                logger.error(f"Failed to process cross-disk duplicate {file_path}: {e}")
                return False

        return True

    def _create_hardlink(self, source: str, duplicate: str) -> bool:
        """Create hardlink and verify"""
        verify = self.config.config.get('safety', {}).get('verify_after_hardlink', True)

        # Get source inode before
        source_stat = os.stat(source)
        source_inode = source_stat.st_ino

        # Create backup if configured
        if self.config.config.get('safety', {}).get('keep_backups', False):
            shutil.copy2(duplicate, f"{duplicate}.backup")

        # Remove duplicate and create hardlink
        os.remove(duplicate)
        os.link(source, duplicate)

        # Verify if enabled
        if verify:
            dup_stat = os.stat(duplicate)
            if dup_stat.st_ino != source_inode:
                logger.error(f"Hardlink verification failed: {duplicate}")
                return False

        logger.info(f"Successfully hardlinked: {duplicate} -> {source}")
        return True


class DedupeManager:
    """Main manager class"""

    def __init__(self, config_path: str = "/data/config/dedupe_config.yaml"):
        self.config = DedupeConfig(config_path)
        self.scanner = RmlintScanner(self.config)
        self.parser = DuplicateParser(self.config)
        self.report_gen = ReportGenerator()
        self.executor = DedupeExecutor(self.config)

    def scan(self, report_id: Optional[str] = None) -> str:
        """Run complete scan and generate reports"""
        if not report_id:
            report_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        report_dir = f"/data/reports/{report_id}"
        os.makedirs(report_dir, exist_ok=True)

        scan_json = f"{report_dir}/scan.json"
        report_json = f"{report_dir}/report.json"
        report_md = f"{report_dir}/report.md"

        # Run rmlint scan
        if not self.scanner.scan(scan_json):
            raise Exception("Scan failed")

        # Parse results
        duplicate_sets = self.parser.parse(scan_json)

        # Generate reports
        self.report_gen.generate_json(duplicate_sets, report_json)
        self.report_gen.generate_markdown(duplicate_sets, report_md)

        logger.info(f"Scan complete. Report ID: {report_id}")
        return report_id

    def execute_report(self, report_id: str) -> Dict:
        """Execute deduplication from report"""
        report_json = f"/data/reports/{report_id}/report.json"

        if not os.path.exists(report_json):
            raise FileNotFoundError(f"Report not found: {report_json}")

        return self.executor.execute(report_json)

    def list_reports(self) -> List[Dict]:
        """List all available reports"""
        reports_dir = "/data/reports"
        if not os.path.exists(reports_dir):
            return []

        reports = []
        for report_id in os.listdir(reports_dir):
            report_path = os.path.join(reports_dir, report_id, "report.json")
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    data = json.load(f)
                    reports.append({
                        'id': report_id,
                        'generated_at': data.get('generated_at'),
                        'summary': data.get('summary')
                    })

        return sorted(reports, key=lambda r: r['generated_at'], reverse=True)

    def get_report(self, report_id: str) -> Optional[Dict]:
        """Get specific report details"""
        report_json = f"/data/reports/{report_id}/report.json"

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

