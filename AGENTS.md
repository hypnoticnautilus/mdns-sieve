# AI Agent Instructions for mDNS Sieve

This file contains important context and commands to help AI agents work effectively on the `mdns-sieve` project. When opening a worktree for this project, you should review this file to understand the architecture and workflows.

## Project Structure
- `py/`: Contains the backend command server and reflector logic (Python).
- `py-gui/`: Contains the frontend graphical user interface (Python).
- `deploy/`: Contains deployment scripts.

## Common Workflows

### Running Tests
The project uses `tox` for testing, linting, and type checking, running in an isolated virtual environment.
Run tests from the root of the project using the `.venv` directory:
```bash
.venv/bin/tox -c py/tox.ini
```

### Deployment
To build the wheel and deploy the updated reflector to the remote Raspberry Pi host (`pi4.home`), use the provided deployment script with the remote virtual environment python path:
```bash
./deploy/reflector.sh pi4.home /tmp/mdns_sieve/venv/bin/python3 /tmp/mdns_sieve/config.yaml
```

## Architecture Notes
- The reflector acts as an mDNS repeater and filter, persisting metrics into an SQLite database (`responses.db`).
- The system catches `SIGINT` and `SIGTERM` signals to cleanly flush databases and exit.
- The `CommandServerManager` handles real-time API requests for statistics over a TCP socket, fetching from both SQLite and active memory buffers.
