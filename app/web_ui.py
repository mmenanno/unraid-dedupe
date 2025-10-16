#!/usr/bin/env python3
"""
Flask Web UI for Unraid Deduplication Manager
"""

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path

import yaml
from flask import Flask, render_template, jsonify, request, send_file

from dedupe_manager import DedupeManager
from scheduler import ScanScheduler, get_cron_presets


# Ensure data directories exist before logging setup
os.makedirs('/data/config', exist_ok=True)
os.makedirs('/data/reports', exist_ok=True)
os.makedirs('/data/logs', exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/data/logs/web_ui.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')


# Global state
manager = DedupeManager()
scheduler = None
scan_status = {
    'running': False,
    'progress': 0,
    'message': 'Idle',
    'report_id': None
}


def scan_callback():
    """Callback function for scheduled scans"""
    logger.info("Scheduled scan triggered")
    trigger_scan()


def trigger_scan():
    """Trigger a scan in background thread"""
    global scan_status

    if scan_status['running']:
        logger.warning("Scan already running")
        return False

    def run_scan():
        global scan_status
        try:
            scan_status['running'] = True
            scan_status['progress'] = 0
            scan_status['message'] = 'Starting scan...'

            logger.info("Starting deduplication scan")
            report_id = manager.scan()

            scan_status['progress'] = 100
            scan_status['message'] = 'Scan complete'
            scan_status['report_id'] = report_id
            logger.info(f"Scan completed: {report_id}")

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            scan_status['message'] = f'Scan failed: {str(e)}'

        finally:
            scan_status['running'] = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    return True


# Initialize scheduler
scheduler = ScanScheduler(scan_callback)

# Log startup information
logger.info("Unraid Deduplication Manager initialized")
logger.info(f"Running in {'production' if not os.environ.get('FLASK_DEBUG', 'False').lower() == 'true' else 'development'} mode")


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
        scan_running=scan_status['running']
    )


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan"""
    if trigger_scan():
        return jsonify({'success': True, 'message': 'Scan started'})
    else:
        return jsonify({'success': False, 'message': 'Scan already running'}), 400


@app.route('/api/scan/status')
def get_scan_status():
    """Get current scan status"""
    return jsonify(scan_status)


@app.route('/api/reports')
def list_reports():
    """List all reports"""
    reports = manager.list_reports()
    return jsonify({'reports': reports})


@app.route('/api/reports/<report_id>')
def get_report(report_id):
    """Get specific report details"""
    report = manager.get_report(report_id)
    if report:
        return jsonify(report)
    else:
        return jsonify({'error': 'Report not found'}), 404


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
def execute_report(report_id):
    """Execute deduplication from report"""
    try:
        stats = manager.execute_report(report_id)
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.error(f"Failed to execute report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reports/<report_id>/download/<file_type>')
def download_report(report_id, file_type):
    """Download report file"""
    if file_type == 'json':
        file_path = f"/data/reports/{report_id}/report.json"
    elif file_type == 'markdown':
        file_path = f"/data/reports/{report_id}/report.md"
    else:
        return "Invalid file type", 400

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404


@app.route('/logs')
def logs_page():
    """Logs viewer page"""
    return render_template('logs.html')


@app.route('/api/logs')
def get_logs():
    """Get recent logs"""
    log_file = '/data/logs/web_ui.log'
    lines = request.args.get('lines', 100, type=int)

    if not os.path.exists(log_file):
        return jsonify({'logs': []})

    try:
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
            recent_lines = all_lines[-lines:]
            return jsonify({'logs': recent_lines})
    except Exception as e:
        logger.error(f"Failed to read logs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/config')
def config_page():
    """Configuration editor page"""
    config = manager.config.config
    return render_template('config.html', config=config)


@app.route('/api/config', methods=['GET', 'POST'])
def config_api():
    """Get or update configuration"""
    if request.method == 'GET':
        return jsonify(manager.config.config)

    elif request.method == 'POST':
        try:
            new_config = request.json

            # Validate YAML structure
            if not isinstance(new_config, dict):
                return jsonify({'success': False, 'error': 'Invalid configuration format'}), 400

            # Required keys
            required_keys = ['scan_paths', 'exclude_patterns', 'path_preferences', 'rmlint_options', 'safety']
            for key in required_keys:
                if key not in new_config:
                    return jsonify({'success': False, 'error': f'Missing required key: {key}'}), 400

            # Save configuration
            manager.config.save(new_config)

            return jsonify({'success': True, 'message': 'Configuration updated'})

        except Exception as e:
            logger.error(f"Failed to update config: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/schedule')
def schedule_page():
    """Schedule configuration page"""
    config = scheduler.get_config()
    presets = get_cron_presets()
    return render_template('schedule.html', config=config, presets=presets)


@app.route('/api/schedule', methods=['GET', 'POST'])
def schedule_api():
    """Get or update schedule configuration"""
    if request.method == 'GET':
        return jsonify(scheduler.get_config())

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
            logger.error(f"Failed to update schedule: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/schedule/enable', methods=['POST'])
def enable_schedule():
    """Enable scheduled scans"""
    if scheduler.enable():
        return jsonify({'success': True, 'message': 'Schedule enabled'})
    else:
        return jsonify({'success': False, 'error': 'Failed to enable schedule'}), 500


@app.route('/api/schedule/disable', methods=['POST'])
def disable_schedule():
    """Disable scheduled scans"""
    if scheduler.disable():
        return jsonify({'success': True, 'message': 'Schedule disabled'})
    else:
        return jsonify({'success': False, 'error': 'Failed to disable schedule'}), 500


@app.route('/api/schedule/trigger', methods=['POST'])
def trigger_schedule():
    """Manually trigger a scan"""
    scheduler.trigger_now()
    return jsonify({'success': True, 'message': 'Scan triggered'})


# Error handlers
@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {e}")
    return render_template('500.html'), 500


# Health check endpoint
@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


def main():
    """Main entry point"""
    # Ensure data directories exist
    os.makedirs('/data/config', exist_ok=True)
    os.makedirs('/data/reports', exist_ok=True)
    os.makedirs('/data/logs', exist_ok=True)

    logger.info("Starting Unraid Deduplication Manager Web UI")
    logger.info("Access the UI at http://localhost:5000")

    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    )


if __name__ == '__main__':
    main()

