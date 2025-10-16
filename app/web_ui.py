#!/usr/bin/env python3
"""
Flask Web UI for Unraid Deduplication Manager
"""

import json
import logging
import os
import re
import secrets
import threading
from datetime import datetime
from typing import Tuple, Dict, Any

import yaml
from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from dedupe_manager import DedupeManager
from scheduler import ScanScheduler, get_cron_presets


# Configure paths from environment variables
DATA_DIR = os.environ.get('DATA_DIR', '/data')
CONFIG_DIR = os.path.join(DATA_DIR, 'config')
REPORTS_DIR = os.path.join(DATA_DIR, 'reports')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')

# Ensure data directories exist before logging setup
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'web_ui.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Initialize Flask app
app = Flask(__name__)

# Generate random secret key if not provided
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    secret_key = secrets.token_hex(32)
    logger.warning("SECRET_KEY not set! Using randomly generated key. Sessions will not persist across restarts.")
    logger.warning("Set SECRET_KEY environment variable for production use.")
app.config['SECRET_KEY'] = secret_key

# Configure rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour", "50 per minute"],
    storage_uri="memory://"
)


class ScanStatus:
    """Encapsulates scan status state with thread safety"""
    def __init__(self):
        self._lock = threading.Lock()
        self.running = False
        self.progress = 0
        self.message = 'Idle'
        self.report_id = None
        self.cancel_requested = False

    def to_dict(self):
        """Convert to dictionary for JSON responses"""
        with self._lock:
            return {
                'running': self.running,
                'progress': self.progress,
                'message': self.message,
                'report_id': self.report_id,
                'cancel_requested': self.cancel_requested
            }

    def reset(self):
        """Reset to initial state"""
        with self._lock:
            self.running = False
            self.progress = 0
            self.message = 'Idle'
            self.report_id = None
            self.cancel_requested = False

    def request_cancel(self):
        """Request scan cancellation"""
        with self._lock:
            self.cancel_requested = True
            logger.info("Scan cancellation requested")

    def is_cancel_requested(self):
        """Check if cancellation has been requested"""
        with self._lock:
            return self.cancel_requested

    def set_running(self, running):
        """Thread-safe setter for running state"""
        with self._lock:
            self.running = running

    def set_progress(self, progress, message):
        """Thread-safe setter for progress"""
        with self._lock:
            self.progress = progress
            self.message = message

    def set_report_id(self, report_id):
        """Thread-safe setter for report_id"""
        with self._lock:
            self.report_id = report_id

    def get_running(self):
        """Thread-safe getter for running state"""
        with self._lock:
            return self.running


# Global state with thread safety
manager = DedupeManager()
scheduler = None
scan_status = ScanStatus()
scan_lock = threading.Lock()


def scan_callback() -> None:
    """Callback function for scheduled scans"""
    logger.info("Scheduled scan triggered")
    trigger_scan()


def trigger_scan() -> bool:
    """Trigger a scan in background thread"""
    global scan_status

    if not scan_lock.acquire(blocking=False):
        logger.warning("Scan already running")
        return False

    if scan_status.get_running():
        scan_lock.release()
        logger.warning("Scan already running")
        return False

    def run_scan():
        global scan_status
        try:
            scan_status.reset()  # Reset status including cancel flag
            scan_status.set_running(True)
            scan_status.set_progress(0, 'Starting scan...')

            logger.info("Starting deduplication scan")

            def update_progress(percent: int, message: str):
                # Check for cancellation
                if scan_status.is_cancel_requested():
                    raise InterruptedError("Scan cancelled by user")
                scan_status.set_progress(percent, message)

            report_id = manager.scan(progress_callback=update_progress)

            if scan_status.is_cancel_requested():
                scan_status.set_progress(0, 'Scan cancelled')
                logger.info("Scan was cancelled")
            else:
                scan_status.set_progress(100, 'Scan complete')
                scan_status.set_report_id(report_id)
                logger.info("Scan completed: %s", report_id)

        except InterruptedError as e:
            logger.info("Scan interrupted: %s", e)
            scan_status.set_progress(0, str(e))
        except Exception as e:
            logger.error("Scan failed: %s", e, exc_info=True)
            scan_status.set_progress(0, f'Scan failed: {str(e)}')

        finally:
            scan_status.set_running(False)
            scan_lock.release()

    thread = threading.Thread(target=run_scan, daemon=False)
    thread.start()
    return True


def cancel_scan() -> bool:
    """Request cancellation of running scan"""
    global scan_status

    if not scan_status.get_running():
        logger.warning("No scan running to cancel")
        return False

    scan_status.request_cancel()
    return True


# Initialize scheduler
scheduler = ScanScheduler(scan_callback)

# Log startup information
logger.info("Unraid Deduplication Manager initialized")
mode = 'production' if not os.environ.get('FLASK_DEBUG', 'False').lower() == 'true' else 'development'
logger.info("Running in %s mode", mode)


# Routes
@app.route('/')
def index():
    """Dashboard page"""
    reports = manager.list_reports()
    latest_report = reports[0] if reports else None
    schedule_config = scheduler.get_config()

    return render_template(
        'index.html',
        latest_report=latest_report,
        schedule_config=schedule_config,
        scan_running=scan_status.get_running()
    )


@app.route('/api/scan/start', methods=['POST'])
@limiter.limit("10 per hour")
def start_scan() -> Tuple[Response, int]:
    """Start a new scan"""
    if trigger_scan():
        return jsonify({'success': True, 'message': 'Scan started'}), 200
    else:
        return jsonify({'success': False, 'message': 'Scan already running'}), 400


@app.route('/api/scan/status')
def get_scan_status() -> Tuple[Response, int]:
    """Get current scan status"""
    return jsonify(scan_status.to_dict()), 200


@app.route('/api/scan/cancel', methods=['POST'])
@limiter.limit("10 per hour")
def cancel_scan_endpoint() -> Tuple[Response, int]:
    """Cancel running scan"""
    if cancel_scan():
        return jsonify({'success': True, 'message': 'Cancellation requested'}), 200
    else:
        return jsonify({'success': False, 'message': 'No scan running'}), 400


@app.route('/api/reports')
def list_reports() -> Tuple[Response, int]:
    """List all reports with pagination support"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    page = max(1, page)
    per_page = min(max(1, per_page), 100)

    all_reports = manager.list_reports()
    total = len(all_reports)

    start = (page - 1) * per_page
    end = start + per_page
    paginated_reports = all_reports[start:end]

    return jsonify({
        'reports': paginated_reports,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }
    }), 200


@app.route('/api/reports/<report_id>')
def get_report(report_id: str) -> Tuple[Response, int]:
    """Get specific report details with optional filtering"""
    report = manager.get_report(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404

    action_filter = request.args.get('action')
    if action_filter and 'duplicate_sets' in report:
        report['duplicate_sets'] = [
            ds for ds in report['duplicate_sets']
            if ds.get('action') == action_filter
        ]

    return jsonify(report), 200


@app.route('/api/reports/<report_id>', methods=['DELETE'])
@limiter.limit("10 per hour")
def delete_report(report_id: str) -> Tuple[Response, int]:
    """Delete a report"""
    if not re.match(r'^[a-zA-Z0-9_-]+$', report_id):
        return jsonify({'error': 'Invalid report ID'}), 400

    report_dir = os.path.join(REPORTS_DIR, report_id)

    if not os.path.exists(report_dir):
        return jsonify({'error': 'Report not found'}), 404

    try:
        import shutil
        shutil.rmtree(report_dir)
        logger.info(f"Deleted report: {report_id}")
        return jsonify({'success': True, 'message': 'Report deleted'}), 200
    except Exception as e:
        logger.error(f"Failed to delete report {report_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/reports')
def reports_page():
    """Reports list page"""
    return render_template('reports.html')


@app.route('/reports/<report_id>')
def report_detail_page(report_id):
    """Report detail page"""
    report = manager.get_report(report_id)
    if not report:
        return "Report not found", 404
    return render_template('report.html', report_id=report_id, report=report)


@app.route('/api/reports/<report_id>/execute', methods=['POST'])
@limiter.limit("5 per hour")
def execute_report(report_id: str) -> Tuple[Response, int]:
    """Execute deduplication from report"""
    try:
        stats = manager.execute_report(report_id)
        return jsonify({'success': True, 'stats': stats}), 200
    except Exception as e:
        logger.error("Failed to execute report: %s", e)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reports/<report_id>/download/<file_type>')
def download_report(report_id: str, file_type: str) -> Tuple[Response, int]:
    """Download report file"""
    if not re.match(r'^[a-zA-Z0-9_-]+$', report_id):
        return jsonify({'error': 'Invalid report ID'}), 400

    if file_type == 'json':
        file_path = os.path.join(REPORTS_DIR, report_id, 'report.json')
    elif file_type == 'markdown':
        file_path = os.path.join(REPORTS_DIR, report_id, 'report.md')
    else:
        return jsonify({'error': 'Invalid file type'}), 400

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return jsonify({'error': 'File not found'}), 404


@app.route('/logs')
def logs_page():
    """Logs viewer page"""
    return render_template('logs.html')


@app.route('/api/logs')
def get_logs() -> Tuple[Response, int]:
    """Get recent logs"""
    log_file = os.path.join(LOGS_DIR, 'web_ui.log')
    lines = request.args.get('lines', 100, type=int)
    lines = min(lines, 10000)

    if not os.path.exists(log_file):
        return jsonify({'logs': []})

    try:
        import subprocess
        result = subprocess.run(
            ['tail', '-n', str(lines), log_file],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            recent_lines = result.stdout.splitlines(keepends=True)
            return jsonify({'logs': recent_lines})
        else:
            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                recent_lines = all_lines[-lines:]
                return jsonify({'logs': recent_lines})
    except subprocess.TimeoutExpired:
        logger.error("Timeout reading logs")
        return jsonify({'error': 'Timeout reading logs'}), 500
    except Exception as e:
        logger.error("Failed to read logs: %s", e)
        return jsonify({'error': str(e)}), 500


@app.route('/config')
def config_page():
    """Configuration editor page"""
    config = manager.config.config
    return render_template('config.html', config=config)


@app.route('/api/config', methods=['GET', 'POST'])
def config_api() -> Tuple[Response, int]:
    """Get or update configuration"""
    if request.method == 'GET':
        return jsonify(manager.config.config), 200

    elif request.method == 'POST':
        try:
            new_config = request.json
            if new_config is None:
                return jsonify({'success': False, 'error': 'Invalid JSON or empty request body'}), 400

            if not isinstance(new_config, dict):
                return jsonify({'success': False, 'error': 'Invalid configuration format'}), 400

            required_keys = ['scan_paths', 'exclude_patterns', 'path_preferences', 'rmlint_options', 'safety']
            for key in required_keys:
                if key not in new_config:
                    return jsonify({'success': False, 'error': f'Missing required key: {key}'}), 400

            if not isinstance(new_config.get('scan_paths'), list):
                return jsonify({'success': False, 'error': 'scan_paths must be a list'}), 400

            if not isinstance(new_config.get('exclude_patterns'), list):
                return jsonify({'success': False, 'error': 'exclude_patterns must be a list'}), 400

            if not isinstance(new_config.get('path_preferences'), list):
                return jsonify({'success': False, 'error': 'path_preferences must be a list'}), 400

            for pref in new_config.get('path_preferences', []):
                if not isinstance(pref, dict):
                    return jsonify({'success': False, 'error': 'Each path preference must be a dict'}), 400
                if 'pattern' not in pref or 'priority' not in pref:
                    return jsonify({'success': False, 'error': 'Path preferences must have pattern and priority'}), 400
                if not isinstance(pref.get('priority'), int):
                    return jsonify({'success': False, 'error': 'Priority must be an integer'}), 400

            if not isinstance(new_config.get('rmlint_options'), dict):
                return jsonify({'success': False, 'error': 'rmlint_options must be a dict'}), 400

            if not isinstance(new_config.get('safety'), dict):
                return jsonify({'success': False, 'error': 'safety must be a dict'}), 400

            manager.config.save(new_config)
            manager.reload_config()

            return jsonify({'success': True, 'message': 'Configuration updated'})

        except Exception as e:
            logger.error("Failed to update config: %s", e)
            return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/schedule')
def schedule_page():
    """Schedule configuration page"""
    config = scheduler.get_config()
    presets = get_cron_presets()
    return render_template('schedule.html', config=config, presets=presets)


@app.route('/api/schedule', methods=['GET', 'POST'])
def schedule_api() -> Tuple[Response, int]:
    """Get or update schedule configuration"""
    if request.method == 'GET':
        return jsonify(scheduler.get_config()), 200

    elif request.method == 'POST':
        try:
            data = request.json
            enabled = data.get('enabled', False)
            cron = data.get('cron', '0 2 * * 0')
            description = data.get('description', '')

            if scheduler.update_config(enabled, cron, description):
                return jsonify({'success': True, 'message': 'Schedule updated'})
            else:
                return jsonify({'success': False, 'error': 'Failed to update schedule'}), 500

        except Exception as e:
            logger.error("Failed to update schedule: %s", e)
            return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/schedule/enable', methods=['POST'])
def enable_schedule() -> Tuple[Response, int]:
    """Enable scheduled scans"""
    if scheduler.enable():
        return jsonify({'success': True, 'message': 'Schedule enabled'}), 200
    else:
        return jsonify({'success': False, 'error': 'Failed to enable schedule'}), 500


@app.route('/api/schedule/disable', methods=['POST'])
def disable_schedule() -> Tuple[Response, int]:
    """Disable scheduled scans"""
    if scheduler.disable():
        return jsonify({'success': True, 'message': 'Schedule disabled'}), 200
    else:
        return jsonify({'success': False, 'error': 'Failed to disable schedule'}), 500


@app.route('/api/schedule/trigger', methods=['POST'])
def trigger_schedule() -> Tuple[Response, int]:
    """Manually trigger a scan"""
    scheduler.trigger_now()
    return jsonify({'success': True, 'message': 'Scan triggered'}), 200


# Error handlers
@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error("Server error: %s", e)
    return render_template('500.html'), 500


# Health check endpoint
@app.route('/api/version')
def get_version() -> Tuple[Response, int]:
    """Get application version"""
    # Try multiple locations for VERSION file (local dev vs Docker)
    possible_paths = [
        os.path.join(os.path.dirname(__file__), 'VERSION'),  # /app/VERSION (Docker)
        os.path.join(os.path.dirname(os.path.dirname(__file__)), 'VERSION'),  # ../VERSION (local dev)
    ]

    for version_file in possible_paths:
        try:
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    version = f.read().strip()
                return jsonify({'version': version}), 200
        except Exception as e:
            logger.debug(f"Failed to read version from {version_file}: {e}")
            continue

    logger.warning("VERSION file not found in any expected location")
    return jsonify({'version': 'unknown'}), 200


@app.route('/api/stats/overview')
def get_stats_overview() -> Tuple[Response, int]:
    """Get aggregate statistics across all reports"""
    try:
        reports = manager.list_reports()

        if not reports:
            return jsonify({
                'total_reports': 0,
                'total_space_saved': 0,
                'total_duplicate_sets': 0,
                'recent_scans': []
            }), 200

        total_space = sum(r.get('summary', {}).get('total_reclaimable', 0) for r in reports)
        total_sets = sum(r.get('summary', {}).get('total_sets', 0) for r in reports)

        # Get recent activity (last 5 reports)
        recent = []
        for r in reports[:5]:
            recent.append({
                'id': r.get('id'),
                'generated_at': r.get('generated_at'),
                'total_sets': r.get('summary', {}).get('total_sets', 0),
                'reclaimable_space': r.get('summary', {}).get('total_reclaimable', 0)
            })

        return jsonify({
            'total_reports': len(reports),
            'total_space_found': total_space,
            'total_duplicate_sets': total_sets,
            'recent_scans': recent
        }), 200
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/validate', methods=['POST'])
def validate_config() -> Tuple[Response, int]:
    """Validate configuration without saving"""
    try:
        config = request.json
        if not config:
            return jsonify({'valid': False, 'errors': ['No configuration provided']}), 400

        errors = []
        warnings = []

        # Validate scan paths
        if not config.get('scan_paths'):
            errors.append('At least one scan path is required')
        else:
            for path in config.get('scan_paths', []):
                if not os.path.exists(path):
                    warnings.append(f'Path does not exist: {path}')
                elif not os.path.isdir(path):
                    errors.append(f'Path is not a directory: {path}')
                elif not os.access(path, os.R_OK):
                    errors.append(f'Path is not readable: {path}')

        # Validate safety options
        safety = config.get('safety', {})
        cross_disk_action = safety.get('cross_disk_action', 'skip')
        if cross_disk_action == 'delete_duplicate':
            warnings.append('Cross-disk delete is enabled - this will permanently delete files!')

        # Validate path preferences
        for pref in config.get('path_preferences', []):
            if not pref.get('pattern'):
                errors.append('Path preference pattern cannot be empty')
            if not isinstance(pref.get('priority'), int) or pref.get('priority') < 1:
                errors.append('Path preference priority must be a positive integer')

        return jsonify({
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }), 200

    except Exception as e:
        logger.error(f"Failed to validate config: {e}")
        return jsonify({'valid': False, 'errors': [str(e)]}), 500


@app.route('/api/schedule/preview')
def preview_schedule() -> Tuple[Response, int]:
    """Preview next run times for a cron expression"""
    try:
        cron_expr = request.args.get('cron', '0 2 * * 0')

        from croniter import croniter
        from datetime import datetime

        if not croniter.is_valid(cron_expr):
            return jsonify({'valid': False, 'error': 'Invalid cron expression'}), 400

        base = datetime.now()
        cron = croniter(cron_expr, base)

        next_runs = []
        for _ in range(5):
            next_run = cron.get_next(datetime)
            next_runs.append(next_run.strftime('%Y-%m-%d %H:%M:%S'))

        return jsonify({
            'valid': True,
            'next_runs': next_runs
        }), 200

    except Exception as e:
        logger.error(f"Failed to preview schedule: {e}")
        return jsonify({'valid': False, 'error': str(e)}), 400


@app.route('/health')
def health() -> Tuple[Response, int]:
    """Health check endpoint with dependency verification"""
    health_status: Dict[str, Any] = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'checks': {}
    }

    try:
        test_file = os.path.join(DATA_DIR, '.health_check')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        health_status['checks']['data_directory'] = 'ok'
    except Exception as e:
        health_status['checks']['data_directory'] = f'error: {str(e)}'
        health_status['status'] = 'unhealthy'

    try:
        if scheduler and scheduler.scheduler.running:
            health_status['checks']['scheduler'] = 'ok'
        else:
            health_status['checks']['scheduler'] = 'not running'
            health_status['status'] = 'degraded'
    except Exception as e:
        health_status['checks']['scheduler'] = f'error: {str(e)}'
        health_status['status'] = 'degraded'

    status_code = 200 if health_status['status'] == 'healthy' else 503
    return jsonify(health_status), status_code


def main() -> None:
    """Main entry point"""
    logger.info("Starting Unraid Deduplication Manager Web UI")
    logger.info("Access the UI at http://localhost:5000")

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    )


if __name__ == '__main__':
    main()

