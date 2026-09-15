# AI Agent Instructions for mDNS Sieve

This file contains important context and commands to help AI agents work effectively on the `mdns-sieve` project. When opening a worktree for this project, you should review this file to understand the architecture and workflows.

## Project Structure
- `rs/`: Contains the core backend reflector daemon, SQLite database telemetry logic, and the embedded `axum` web GUI (Rust).
- `pkg/apk/`: Contains Alpine Linux packaging scripts and Docker build configuration.
- `.local/`: Used for local configurations, mock environments, and deployment scripts (e.g., `deploy.sh`). This is not checked in.
- `py/` & `py-gui/`: Legacy Python implementations (deprecated/unmaintained, kept for reference).

## Common Workflows

### Building & Packaging
The project is built using Cargo in the `rs/` directory. Alpine APKs are packaged via Docker to ensure clean cross-compilation environments.
```bash
# Compile Rust binary dynamically for target arch (using messense/rust-musl-cross)
./rs/cargo.sh build --release --target <target-triple>

# Package APKs using Docker (supports optional -k <private-key> for abuild signing)
./pkg/apk/docker_build.sh [-k <path-to-privkey>] -a <architecture> -o <output-dir> <path-to-binary>
```

### GitHub Actions CI / Release
Automated cross-compilation and Alpine packaging workflows are defined in `.github/workflows/build.yml`.
- Builds packages for `x86_64` and `aarch64` architectures.
- Triggered manually via `workflow_dispatch` or on version tags (`v*`).
- Generates Draft GitHub Releases when a tag is pushed.
- Uses `PACKAGING_RSA_KEY` secret if configured in GitHub repository secrets, falling back to ephemeral keys if omitted.

### Deployment
Use the local deployment script to push updates to target hosts (e.g., Alpine on Raspberry Pi). This script detects remote host architecture, automatically compiles and packages via Docker, generates a signed index, and installs via Alpine's local repository feature over SSH.
```bash
./.local/deploy.sh pi3.home
```

## Architecture Notes

### Database Persistence & Telemetry Tracking
- The reflector acts as an mDNS repeater and filter, persisting metrics into an SQLite database (by default at `/var/lib/mdns-sieve/responses.db` containing `responses`, `queries`, and `global_stats` tables).
- The system catches `SIGINT` and `SIGTERM` signals to cleanly flush databases and exit.
- Tracking logic is contained in `rs/src/database.rs`.
- Memory buffers are periodically flushed to the database and pruned based on `retention_days`. When writing unit tests with mock timestamps, always use current times rather than older epoch constants to prevent records from being immediately pruned by the retention manager.

### Command API & Embedded GUI
- The daemon features an embedded web server running on `axum` (`rs/src/server.rs`) which exposes both the JSON API and the dashboard GUI.
- `/api/stats`: Returns aggregated global packets counts (`total`, `forwarded`, `dropped`, `rewritten`), daemon version, and commit information.
- `/api/hosts`: Returns a dictionary mapping host IPs to packet counts, last interface, and last seen timestamps.
- `/api/names`: Returns nested maps of `responses` and `queries` aggregated by service name and source IP. Includes `src` (source interfaces list), `fwd` (forwarded interfaces list), and `drop` (dropped interfaces list) to allow precise interface filtering.
- `/api/host_details?ip=<ip>`: Returns detailed list of queries and responses recorded for a specific source IP.
- `/api/clear` (POST): Resets statistics. Passing a JSON payload `{"clear_tracking": true}` will also purge all query/response database tables and active memory buffers.
