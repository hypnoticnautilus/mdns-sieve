"""
mDNS Sieve Web GUI Backend Server

Hosts the HTTP server, serves the compiled frontend assets,
and translates HTTP requests into TCP command socket communication with the daemon.
"""

import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging
import pkgutil
import socket
import sys
import urllib.parse
from typing import Dict, Any, Union

import yaml

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mdns_sieve_gui")


def get_gui_commit() -> str:
    # pylint: disable=import-outside-toplevel,broad-exception-caught
    """Attempts to load build-time stamped commit, with developer dynamic fallback."""
    try:
        from mdns_sieve_gui._version import __commit__

        if __commit__ != "unknown":
            return __commit__
    except (ImportError, ModuleNotFoundError):
        pass

    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=1.0,
        )
        git_val = result.stdout.strip()
        if git_val:
            return git_val
    except Exception:
        pass

    return "unknown"


def query_daemon(host: str, port: int, command: Union[str, Dict[str, Any]]) -> str:
    """Connects to the daemon TCP command server, sends the command, and returns the response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    try:
        sock.connect((host, port))
        if isinstance(command, dict):
            payload = json.dumps(command).encode("utf-8") + b"\x00"
        else:
            payload = json.dumps({"command": command}).encode("utf-8") + b"\x00"
        sock.sendall(payload)

        buffer = bytearray()
        while b"\x00" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer.extend(chunk)
            if len(buffer) > 10 * 1024 * 1024:  # 10MB safety limit
                raise ValueError("Response from daemon too large")

        if b"\x00" in buffer:
            idx = buffer.index(b"\x00")
            return buffer[:idx].decode("utf-8")
        raise ConnectionError("Connection closed before response delimiter was received")
    finally:
        sock.close()


class SieveHTTPServer(HTTPServer):
    """Extends standard HTTPServer to store daemon connection details."""

    def __init__(
        self,
        server_address: Any,
        RequestHandlerClass: Any,
        daemon_host: str,
        daemon_port: int,
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.daemon_host = daemon_host
        self.daemon_port = daemon_port


# pylint: disable=invalid-name
class SieveGUIHandler(BaseHTTPRequestHandler):
    """Custom HTTP Request Handler serving static frontend files and proxying API endpoints."""

    # pylint: disable=redefined-builtin
    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard http.server logger outputs to debug level."""
        logger.debug(format, *args)

    def do_GET(self) -> None:
        """Handles HTTP GET requests."""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path in ("/", "/index.html"):
            self._serve_asset("static/index.html", "text/html; charset=utf-8")
        elif path == "/style.css":
            self._serve_asset("static/style.css", "text/css; charset=utf-8")
        elif path == "/app.js":
            self._serve_asset("static/app.js", "application/javascript; charset=utf-8")
        elif path == "/favicon.svg":
            self._serve_asset("static/favicon.svg", "image/svg+xml")
        elif path in ("/api/stats", "/api/hosts", "/api/names"):
            cmd = path.split("/")[-1]
            self._handle_api_command(cmd)
        elif path == "/api/host_details":
            query = urllib.parse.parse_qs(parsed_path.query)
            ip = query.get("ip", [""])[0]
            if not ip:
                self._send_json({"status": "error", "error": "Missing ip parameter"}, 400)
                return
            self._handle_api_command({"command": "host_details", "ip": ip})
        else:
            self._send_json({"status": "error", "error": "Not Found"}, 404)

    def do_POST(self) -> None:
        """Handles HTTP POST requests."""
        if self.path == "/api/clear":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length) if content_length > 0 else b""
            clear_tracking = False
            if post_data:
                try:
                    payload = json.loads(post_data.decode("utf-8"))
                    if isinstance(payload, dict):
                        clear_tracking = bool(payload.get("clear_tracking", False))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            self._handle_api_command({"command": "clear", "clear_tracking": clear_tracking})
        else:
            self._send_json({"status": "error", "error": "Not Found"}, 404)

    def _serve_asset(self, resource_path: str, content_type: str) -> None:
        """Loads and writes static package data."""
        try:
            data = pkgutil.get_data("mdns_sieve_gui", resource_path)
            if data is None:
                self._send_json({"status": "error", "error": "Asset not found"}, 404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self._send_json({"status": "error", "error": "Asset read error"}, 500)

    def _handle_api_command(self, cmd: Union[str, Dict[str, Any]]) -> None:
        """Proxies API command calls directly to the daemon's TCP server."""
        try:
            host = self.server.daemon_host  # type: ignore[attr-defined]
            port = self.server.daemon_port  # type: ignore[attr-defined]
            resp_str = query_daemon(host, port, cmd)

            # Intercept stats command to inject GUI commit and version
            if cmd == "stats" or (isinstance(cmd, dict) and cmd.get("command") == "stats"):
                try:
                    resp_data = json.loads(resp_str)
                    if isinstance(resp_data, dict):
                        resp_data["gui_commit"] = get_gui_commit()
                        resp_data["gui_version"] = "0.1.0"
                        resp_str = json.dumps(resp_data)
                except Exception as e:  # pylint: disable=broad-exception-caught
                    logger.error("Failed to parse/enrich daemon stats response: %s", str(e))

            resp_bytes = resp_str.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error communicating with daemon: %s", str(e))
            self._send_json(
                {
                    "status": "error",
                    "error": "Daemon connection failed",
                    "message": str(e),
                },
                502,
            )

    def _send_json(self, data: Dict[str, Any], status: int) -> None:
        """Encodes and writes a JSON API response."""
        try:
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass


def load_config_file(config_path: str) -> Dict[str, Any]:
    """Attempts to load configuration overrides from YAML file."""
    overrides: Dict[str, Any] = {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            cmd_cfg = data.get("command_server")
            if isinstance(cmd_cfg, dict):
                host = cmd_cfg.get("host")
                port = cmd_cfg.get("port")
                if host is not None:
                    overrides["daemon_host"] = str(host)
                if port is not None:
                    overrides["daemon_port"] = int(port)

            gui_cfg = data.get("gui_server")
            if isinstance(gui_cfg, dict):
                host = gui_cfg.get("host")
                port = gui_cfg.get("port")
                if host is not None:
                    overrides["web_host"] = str(host)
                if port is not None:
                    overrides["web_port"] = int(port)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to parse configuration file %s: %s", config_path, str(e))
    return overrides


def main() -> None:
    """CLI execution entrypoint."""
    parser = argparse.ArgumentParser(description="mDNS Sieve Web GUI Dashboard")
    parser.add_argument("-c", "--config", help="Path to daemon YAML config file")
    parser.add_argument("--host", help="Daemon TCP server host")
    parser.add_argument("--port", type=int, help="Daemon TCP server port")
    parser.add_argument("--web-host", help="GUI web server listen address (default: 0.0.0.0)")
    parser.add_argument("--web-port", type=int, help="GUI web server listen port (default: 8080)")

    args = parser.parse_args()

    daemon_host = "127.0.0.1"
    daemon_port = 5354
    web_host = "0.0.0.0"
    web_port = 8080

    if args.config:
        cfg = load_config_file(args.config)
        daemon_host = cfg.get("daemon_host", daemon_host)
        daemon_port = cfg.get("daemon_port", daemon_port)
        web_host = cfg.get("web_host", web_host)
        web_port = cfg.get("web_port", web_port)

    if args.host is not None:
        daemon_host = args.host
    if args.port is not None:
        daemon_port = args.port
    if args.web_host is not None:
        web_host = args.web_host
    if args.web_port is not None:
        web_port = args.web_port

    logger.info("Connecting to mDNS Sieve daemon at %s:%d", daemon_host, daemon_port)
    logger.info("Starting Web GUI Server on http://%s:%d", web_host, web_port)

    try:
        httpd = SieveHTTPServer(
            (web_host, web_port),
            SieveGUIHandler,
            daemon_host,
            daemon_port,
        )
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Web GUI Server...")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.critical("Server crash: %s", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
