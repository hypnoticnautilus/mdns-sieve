"""
Test Suite for mDNS Sieve Web GUI

Tests static file routing, API proxy queries, daemon connection failures,
and command-line configuration loading.
"""

import io
import json
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch
import urllib.request
import urllib.error

from mdns_sieve_gui.main import (
    SieveHTTPServer,
    SieveGUIHandler,
    load_config_file,
    query_daemon,
    main,
)


class TestGUIConfig(unittest.TestCase):
    """Verifies GUI configuration parsing and overrides."""

    def test_load_config_file(self) -> None:
        """Verifies loading settings from config YAML."""
        yaml_content = """
command_server:
  enabled: true
  host: "10.0.0.25"
  port: 9999
gui_server:
  host: "192.168.1.10"
  port: 9090
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_content)):
            cfg = load_config_file("dummy.yaml")
            self.assertEqual(cfg.get("daemon_host"), "10.0.0.25")
            self.assertEqual(cfg.get("daemon_port"), 9999)
            self.assertEqual(cfg.get("web_host"), "192.168.1.10")
            self.assertEqual(cfg.get("web_port"), 9090)

    def test_load_config_file_omitted(self) -> None:
        """Verifies parsing of empty or missing config blocks."""
        yaml_content = """
interfaces: [eth0]
"""
        with patch("builtins.open", return_value=io.StringIO(yaml_content)):
            cfg = load_config_file("dummy.yaml")
            self.assertNotIn("daemon_host", cfg)
            self.assertNotIn("daemon_port", cfg)
            self.assertNotIn("web_host", cfg)
            self.assertNotIn("web_port", cfg)

    @patch("mdns_sieve_gui.main.SieveHTTPServer")
    @patch("mdns_sieve_gui.main.load_config_file")
    def test_main_cli_overrides_config(
        self, mock_load: MagicMock, mock_server_class: MagicMock
    ) -> None:
        """Verifies that CLI flags override config file values."""
        mock_load.return_value = {
            "daemon_host": "10.0.0.1",
            "daemon_port": 1111,
            "web_host": "127.0.0.1",
            "web_port": 2222,
        }

        test_args = [
            "mdns-sieve-gui",
            "--config",
            "dummy.yaml",
            "--host",
            "192.168.1.1",
            "--port",
            "3333",
            "--web-host",
            "0.0.0.0",
            "--web-port",
            "4444",
        ]
        with patch("sys.argv", test_args):
            main()

        mock_server_class.assert_called_once_with(
            ("0.0.0.0", 4444), unittest.mock.ANY, "192.168.1.1", 3333
        )

    @patch("mdns_sieve_gui.main.SieveHTTPServer")
    @patch("mdns_sieve_gui.main.load_config_file")
    def test_main_uses_config(self, mock_load: MagicMock, mock_server_class: MagicMock) -> None:
        """Verifies that config values are used when no CLI flags override them."""
        mock_load.return_value = {
            "daemon_host": "10.0.0.1",
            "daemon_port": 1111,
            "web_host": "192.168.1.5",
            "web_port": 2222,
        }
        test_args = ["mdns-sieve-gui", "--config", "dummy.yaml"]
        with patch("sys.argv", test_args):
            main()

        mock_server_class.assert_called_once_with(
            ("192.168.1.5", 2222), unittest.mock.ANY, "10.0.0.1", 1111
        )

    @patch("mdns_sieve_gui.main.SieveHTTPServer")
    @patch("mdns_sieve_gui.main.load_config_file")
    def test_main_uses_defaults(self, mock_load: MagicMock, mock_server_class: MagicMock) -> None:
        """Verifies that standard defaults are used if no config or CLI overrides exist."""
        test_args = ["mdns-sieve-gui"]
        with patch("sys.argv", test_args):
            main()

        mock_server_class.assert_called_once_with(
            ("0.0.0.0", 8080), unittest.mock.ANY, "127.0.0.1", 5354
        )
        mock_load.assert_not_called()


class TestGUIIntegration(unittest.TestCase):
    """Integration tests running SieveHTTPServer on an ephemeral port."""

    server: SieveHTTPServer
    server_thread: threading.Thread
    port: int

    @classmethod
    def setUpClass(cls) -> None:
        # Spin up GUI server on a random local free port (port 0)
        cls.server = SieveHTTPServer(("127.0.0.1", 0), SieveGUIHandler, "127.0.0.1", 5354)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def test_static_assets(self) -> None:
        """Verifies that static assets (HTML, CSS, JS) are served correctly."""
        # index.html (root)
        url = f"http://127.0.0.1:{self.port}/"
        with urllib.request.urlopen(url) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("text/html", res.info().get("Content-Type", ""))
            self.assertIn(b"mDNS Sieve Dashboard", res.read())

        # style.css
        url = f"http://127.0.0.1:{self.port}/style.css"
        with urllib.request.urlopen(url) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("text/css", res.info().get("Content-Type", ""))

        # app.js
        url = f"http://127.0.0.1:{self.port}/app.js"
        with urllib.request.urlopen(url) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("application/javascript", res.info().get("Content-Type", ""))

        # favicon.svg
        url = f"http://127.0.0.1:{self.port}/favicon.svg"
        with urllib.request.urlopen(url) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("image/svg+xml", res.info().get("Content-Type", ""))

    def test_missing_route(self) -> None:
        """Verifies wrong paths return 404."""
        url = f"http://127.0.0.1:{self.port}/invalid-page"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            with urllib.request.urlopen(url):
                pass
        self.assertEqual(ctx.exception.code, 404)

    @patch("mdns_sieve_gui.main.query_daemon")
    def test_api_proxy_success(self, mock_query: MagicMock) -> None:
        """Verifies successful proxying of API GET routes to the daemon."""
        mock_query.return_value = '{"status": "ok", "data": {"total": 5}}'

        url = f"http://127.0.0.1:{self.port}/api/stats"
        with urllib.request.urlopen(url) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("application/json", res.info().get("Content-Type", ""))
            body = json.loads(res.read().decode("utf-8"))

        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["data"]["total"], 5)

        mock_query.assert_called_once_with("127.0.0.1", 5354, "stats")

    @patch("mdns_sieve_gui.main.query_daemon")
    def test_api_proxy_clear(self, mock_query: MagicMock) -> None:
        """Verifies proxying of clear stats POST route."""
        mock_query.return_value = '{"status": "ok"}'

        url = f"http://127.0.0.1:{self.port}/api/clear"
        req = urllib.request.Request(url, method="POST")
        with urllib.request.urlopen(req) as res:
            self.assertEqual(res.status, 200)
            body = json.loads(res.read().decode("utf-8"))

        self.assertEqual(body["status"], "ok")

        mock_query.assert_called_once_with("127.0.0.1", 5354, "clear")

    @patch("mdns_sieve_gui.main.query_daemon")
    def test_api_proxy_failure(self, mock_query: MagicMock) -> None:
        """Verifies API returns 502 if daemon is offline."""
        mock_query.side_effect = ConnectionRefusedError("Connection refused")

        url = f"http://127.0.0.1:{self.port}/api/stats"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            with urllib.request.urlopen(url):
                pass
        self.assertEqual(ctx.exception.code, 502)

        body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(body["status"], "error")
        self.assertEqual(body["error"], "Daemon connection failed")


class TestSocketExchange(unittest.TestCase):
    """Tests the raw socket TCP client queries in query_daemon."""

    @patch("socket.socket")
    def test_query_daemon_exchange(self, mock_socket: MagicMock) -> None:
        """Verifies normal JSON packet exchange and null-byte termination handling."""
        mock_inst = MagicMock()
        mock_socket.return_value = mock_inst

        # Response chunk list
        mock_inst.recv.side_effect = [b'{"status": "ok"}', b"\x00"]

        resp = query_daemon("127.0.0.1", 5354, "stats")
        self.assertEqual(resp, '{"status": "ok"}')

        mock_inst.connect.assert_called_once_with(("127.0.0.1", 5354))
        mock_inst.sendall.assert_called_once_with(b'{"command": "stats"}\x00')

    @patch("socket.socket")
    def test_query_daemon_timeout(self, mock_socket: MagicMock) -> None:
        """Verifies socket timeout error propagation."""
        mock_inst = MagicMock()
        mock_socket.return_value = mock_inst
        mock_inst.connect.side_effect = socket.timeout("timeout")

        with self.assertRaises(socket.timeout):
            query_daemon("127.0.0.1", 5354, "stats")


if __name__ == "__main__":
    unittest.main()
