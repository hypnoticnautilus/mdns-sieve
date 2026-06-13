# AI Agent Instructions for mDNS Sieve

This file contains important context and commands to help AI agents work effectively on the `mdns-sieve` project. When opening a worktree for this project, you should review this file to understand the architecture and workflows.

## Project Structure
- `py/`: Contains the backend command server and reflector logic (Python).
- `py-gui/`: Contains the frontend graphical user interface (Python).
- `deploy/`: Contains deployment scripts.

## Common Workflows

### Running Tests
The project uses `tox` for testing, linting, and type checking, running in an isolated virtual environment. 
To test both the backend and frontend modules:
```bash
.venv/bin/tox -c py/tox.ini
.venv/bin/tox -c py-gui/tox.ini
```

### Deployment
To build the wheels and deploy the updated reflector or GUI to the remote Raspberry Pi host (`pi4.home`), use the provided deployment scripts with the remote virtual environment python path:
```bash
./deploy/reflector.sh pi4.home /tmp/mdns_sieve/venv/bin/python3 /tmp/mdns_sieve/config.yaml
./deploy/gui.sh pi4.home /tmp/mdns_sieve/venv/bin/python3 /tmp/mdns_sieve/config.yaml
```

## Architecture Notes

### Database Persistence & Telemetry Tracking
- The reflector acts as an mDNS repeater and filter, persisting metrics into an SQLite database (by default at `/var/lib/mdns-sieve/responses.db` containing `responses`, `queries`, and `global_stats` tables).
- The system catches `SIGINT` and `SIGTERM` signals to cleanly flush databases and exit.
- The `CommandServerManager` handles real-time API requests for statistics over a TCP socket. It fetches records from SQLite, merges them with active memory buffers, and **pre-aggregates** the metrics at the Python level to optimize network payloads.
- **Database Pruning**: Memory buffers are periodically flushed to the database and pruned based on `retention_days`. When writing unit tests with mock timestamps, always use current times (e.g. `time.time()`) rather than older epoch constants to prevent records from being immediately pruned by the retention manager.

### Command API Endpoints
- `/api/stats`: Returns aggregated global packets counts (`total`, `forwarded`, `dropped`, `rewritten`), daemon version, and commit information.
- `/api/hosts`: Returns a dictionary mapping host IPs to packet counts, last interface, and last seen timestamps.
- `/api/names`: Returns nested maps of `responses` and `queries` aggregated by service name and source IP. Includes `src` (source interfaces list), `fwd` (forwarded interfaces list), and `drop` (dropped interfaces list) to allow precise interface filtering.
- `/api/host_details?ip=<ip>`: Returns detailed list of queries and responses recorded for a specific source IP.
- `/api/clear` (POST): Resets statistics. Passing a JSON payload `{"clear_tracking": true}` will also purge all query/response database tables and active memory buffers.

### GUI Layout & Design Rules
- **Viewport Constraints**: The GUI dashboard layout uses a stabilized double-panel grid (each set to exactly `50%` width of the `.split-row` container) with a fixed height viewport constraint (`height: calc(100vh - 48px)`). Dynamic elements (such as searching, filtering, or expanding accordion panels) must never trigger an outer page scrollbar or cause window jumpiness.
- **Modal Scrolling**: The host details modal table has no nested container scrollbars. The scrolling layer is consolidated into the `.modal-body` (flexible flex layout: `flex: 1; overflow-y: auto;` with `max-height: 90vh` on `.modal-card`).
- **Service Name Ellipsizing**: Long mDNS service names are middle-ellipsized (limiting the first service name component to 10 characters, e.g. `_%9...5ED`) while preserving the last three components as they denote the service family/type (e.g., `._sub._googlecast._tcp.local`). A title tooltip must display the full name on hover.
- The GUI (`py-gui`) serves static HTML/JS assets and proxies HTTP `/api/*` endpoints to the daemon's TCP server socket.

