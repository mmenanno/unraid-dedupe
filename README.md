# Unraid Deduplication Manager

A self-contained Docker application for managing file deduplication on Unraid servers. Built with rmlint for efficient duplicate detection, Python for orchestration, and Flask for a user-friendly web interface.

## Features

- **Automated Scanning**: Built-in scheduler for periodic deduplication scans
- **Smart Decision Engine**: Intelligently handles same-disk and cross-disk duplicates with configurable path preferences
- **Web Interface**: Modern, mobile-responsive UI - no SSH required
- **Production Ready**: Runs with Gunicorn WSGI server for stable production deployment
- **Safe Operations**: Dry-run reports, hardlink verification, comprehensive logging
- **Configuration Management**: Full config editing through the web UI
- **Real-time Progress**: Live scan status updates and log streaming

## Quick Start

### Prerequisites

- Unraid server (or any Docker-compatible system)
- Docker installed and running
- Access to your data directories

### Installation on Unraid

1. **Install from Docker Hub** (via Unraid UI):
   - Go to Docker tab
   - Click "Add Container"
   - Configure as follows:

   ```text
   Name: dedupe-manager
   Repository: ghcr.io/mmenanno/unraid-dedupe:latest
   Network Type: bridge

   Port Mappings:
     Container Port: 5000
     Host Port: 5000

   Path Mappings:
     Container Path: /mnt
     Host Path: /mnt
     Access Mode: Read-only (recommended)

     Container Path: /data
     Host Path: /mnt/cache/appdata/dedupe
     Access Mode: Read/Write

   Environment Variables:
     PUID: 99
     PGID: 100
   ```

2. **Start the container**

3. **Access the Web UI**:
   - Navigate to `http://YOUR-SERVER-IP:5000`
   - Example: `http://leviathan:5000`

### Using the Application

#### 1. Configure Settings (First Time Setup)

1. Go to the **Config** tab
2. Set your scan paths (default: `/mnt/user/data`)
3. Add exclude patterns for files/folders to skip
4. Configure path preferences (which locations to prioritize)
5. Save configuration

#### 2. Run a Scan

**Manual Scan:**

1. Go to the **Dashboard**
2. Click "Start Scan"
3. Wait for scan to complete (progress shown in real-time)

**Scheduled Scans:**

1. Go to the **Schedule** tab
2. Enable scheduled scans
3. Choose a preset or enter a custom cron expression
4. Save schedule

#### 3. Review Reports

1. Go to the **Reports** tab
2. Click on a report to view details
3. Review the summary:
   - Same-disk duplicates (safe to process)
   - Cross-disk duplicates (requires migration)
   - Manual review items (ambiguous cases)

#### 4. Execute Deduplication

1. Open a report
2. Review the duplicate sets
3. Click "Execute Deduplication"
4. Confirm the operation
5. Monitor progress in the Logs tab

## Configuration

### Scan Paths

Directories to scan for duplicates. Defaults to `/mnt/user/data`.

```yaml
scan_paths:
  - /mnt/user/data
  - /mnt/user/media
```

### Exclude Patterns

Glob patterns for files/folders to exclude from scanning.

```yaml
exclude_patterns:
  - "*.tmp"
  - "*/.Trash-*"
  - "*/System Volume Information/*"
  - "*/@eaDir/*"  # Synology
  - "*/._*"        # macOS resource forks
```

### Path Preferences

Define which locations should be preferred when choosing which duplicate to keep.

```yaml
path_preferences:
  - pattern: "/mnt/user/data/media/*"
    priority: 1  # Highest priority - keep these
  - pattern: "/mnt/user/data/downloads/*"
    priority: 2  # Lower priority - remove these first
```

**How it works:**

- Lower priority number = higher preference
- The file matching the lowest priority pattern becomes the "keeper"
- Other duplicates are marked for removal
- If priorities tie or no pattern matches, files are flagged for manual review

### Rmlint Options

```yaml
rmlint_options:
  algorithm: "xxhash"  # Options: xxhash, sha256, sha512
```

### Safety Options

```yaml
safety:
  verify_after_hardlink: true  # Verify inode after hardlink creation
  keep_backups: false          # Keep .backup files (not recommended)
  cross_disk_action: "skip"    # How to handle cross-disk duplicates
```

**Cross-Disk Deduplication Options:**

Since hardlinks only work within the same filesystem/disk, cross-disk duplicates require special handling:

- **`skip`** (default): Don't process cross-disk duplicates. Safest option, no risk of data loss, but no space savings across disks.
- **`manual_review`**: Log cross-disk duplicates for manual review. Files are not modified automatically.
- **`delete_duplicate`**: Delete non-preferred duplicates on other disks. **⚠️ WARNING**: This permanently deletes files and loses redundancy across disks. Use with caution!

**Example scenarios:**

If you have `/mnt/disk1/media/movie.mkv` (priority 1) and `/mnt/disk2/downloads/movie.mkv` (priority 2):

- `skip`: Both files remain untouched
- `manual_review`: Both files remain, but logged for your review
- `delete_duplicate`: `/mnt/disk2/downloads/movie.mkv` is deleted, only disk1 copy remains

## Scheduling

The application includes a built-in scheduler (no external cron needed).

### Cron Expression Format

```text
minute hour day month day_of_week
```

**Examples:**

- `0 2 * * 0` - Weekly on Sunday at 2:00 AM
- `0 2 * * *` - Daily at 2:00 AM
- `0 0 1 * *` - Monthly on the 1st at midnight
- `0 */6 * * *` - Every 6 hours

### Common Presets

Available in the Schedule tab:

- Daily at 2 AM
- Weekly (Sunday 2 AM)
- Weekly (Monday 2 AM)
- Bi-weekly (Sunday 2 AM)
- Monthly (1st at 2 AM)
- Every 6 hours
- Every 12 hours

## How Deduplication Works

### 1. Scanning Phase

- rmlint scans specified paths
- Computes checksums for all files (using xxhash by default)
- Groups files with identical checksums

### 2. Analysis Phase

- **Same-disk duplicates**: Files on the same physical disk
  - Action: Direct hardlinking (safe, instant space recovery)

- **Cross-disk duplicates**: Files on different disks
  - Action: Copy keeper to correct disk → hardlink → delete original
  - Path preferences determine which file is the "keeper"

- **Manual review**: Ambiguous cases
  - Action: Flagged for user decision (not processed automatically)

### 3. Execution Phase

- Processes same-disk duplicates first (safest)
- For each duplicate set:
  1. Create hardlink to keeper file
  2. Verify hardlink (compare inodes)
  3. Delete duplicate file
  4. Log operation

### What are Hardlinks?

Hardlinks are multiple directory entries pointing to the same physical file data on disk. They:

- Save space instantly (only one copy of data exists)
- Are transparent to applications (files appear in both locations)
- Only work within the same filesystem/disk
- Are safe (deleting one hardlink doesn't delete the data)

## CLI Usage

You can also run operations via command line:

```bash
# Enter the container
docker exec -it dedupe-manager bash

# Run a scan
python dedupe_manager.py scan

# List reports
python dedupe_manager.py list

# View a report
python dedupe_manager.py report 20241016_120000

# Execute a report
python dedupe_manager.py execute 20241016_120000
```

## Development

### Building Locally

```bash
docker build -t unraid-dedupe .
docker run -p 5000:5000 -v $(pwd)/data:/data unraid-dedupe
```

### Project Structure

```text
unraid-dedupe/
├── Dockerfile                      # Multi-stage build
├── VERSION                         # Version file
├── requirements.txt                # Python dependencies
├── .github/workflows/
│   └── docker-build.yml           # CI/CD pipeline
├── app/
│   ├── dedupe_manager.py          # Core deduplication logic
│   ├── web_ui.py                  # Flask web server
│   ├── scheduler.py               # APScheduler integration
│   ├── templates/                 # HTML templates
│   └── static/                    # CSS and assets
└── config/
    └── dedupe_config.yaml         # Default configuration
```

## Deployment

### Publishing a New Version

1. Update the `VERSION` file:

   ```bash
   echo "1.1.0" > VERSION
   git add VERSION
   git commit -m "Bump version to 1.1.0"
   git push
   ```

2. GitHub Actions automatically:
   - Builds the Docker image
   - Pushes to `ghcr.io/mmenanno/unraid-dedupe:latest`
   - Tags with version: `ghcr.io/mmenanno/unraid-dedupe:1.1.0`

### Manual Deployment Trigger

You can also trigger a build manually via GitHub Actions:

1. Go to Actions tab in GitHub
2. Select "Build and Push Docker Image"
3. Click "Run workflow"

## Troubleshooting

### Container won't start

Check logs:

```bash
docker logs dedupe-manager
```

### Scan fails with "Can't open directory or file" error

This was fixed in recent versions. If you see this error:
- Update to the latest version by rebuilding the container
- The issue was with rmlint exclude pattern syntax (now uses `--exclude` instead of `--match-without-extension`)

### Other scan failures

- Verify scan paths are correct and accessible
- Check permissions on `/mnt` mount
- Review logs in the Logs tab

### Web UI not accessible

- Verify port 5000 is not in use
- Check firewall settings
- Ensure container is running: `docker ps`

### No duplicates found

- Verify scan paths contain files
- Check exclude patterns aren't too broad
- Ensure rmlint is installed: `docker exec dedupe-manager rmlint --version`

## Safety Considerations

- **Always review reports before executing**
- Start with a small test directory first
- Consider running with read-only `/mnt` mount initially
- Keep good backups (this tool doesn't create them)
- For cross-disk duplicates, use `skip` or `manual_review` mode unless you're certain you want to delete duplicates on other disks
- When using `delete_duplicate` for cross-disk, understand that it permanently removes files and you lose redundancy across disks

## Performance

- Scanning speed: ~100-500 MB/s (depends on disk speed)
- xxhash algorithm: Fast and reliable
- Multi-threaded hashing for better performance
- Scan results are reusable (no need to rescan to regenerate reports)

## License

MIT License - feel free to use and modify

## Contributing

Pull requests welcome! Please ensure:

- Code follows existing style
- Comments for complex logic
- Test on Unraid before submitting

## Support

- GitHub Issues: For bugs and feature requests
- Discussions: For questions and community support

## Credits

- Built with [rmlint](https://github.com/sahib/rmlint) by sahib
- Uses Flask, APScheduler, and other open-source libraries
- Inspired by Unraid community deduplication needs
