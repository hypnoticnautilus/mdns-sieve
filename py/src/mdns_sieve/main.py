"""
mDNS Sieve Command Line Interface

Handles daemon invocation, command-line arguments parsing, logging initialization,
and operating system signal traps for clean terminations.
"""

import argparse

import logging
import signal
import sys
from types import FrameType
from typing import Optional

from mdns_sieve.config import load_config, ConfigurationError
from mdns_sieve.reflector import MdnsReflector

# Define highly readable, premium logging format
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_logging(verbose_count: int) -> None:
    """Configures system wide logging format and depth."""
    if verbose_count == 0:
        level = logging.WARNING
    elif verbose_count == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG
    logging.basicConfig(
        level=level, format=LOG_FORMAT, handlers=[logging.StreamHandler(sys.stderr)]
    )


def main() -> None:
    """CLI Entrypoint to parse parameters and boot the reflector daemon."""
    parser = argparse.ArgumentParser(
        description="mdns-sieve: Robust, lightweight, fine-grained mDNS reflector daemon."
    )
    parser.add_argument(
        "-c",
        "--config",
        required=True,
        help="Path to the YAML configuration file defining interfaces and sieve rules.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level (e.g. -v or -vv to capture blocked/repeated packets).",
    )
    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger("mdns_sieve")

    logger.info("Initializing mdns-sieve...")

    try:
        config = load_config(args.config)
    except ConfigurationError as e:
        logger.error("Configuration failure: %s", str(e))
        sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Unexpected error loading configuration: %s", str(e))
        if logger.isEnabledFor(logging.DEBUG):
            logging.exception(e)
        sys.exit(1)

    reflector = MdnsReflector(config)

    def signal_handler(signum: int, frame: Optional[FrameType]) -> None:
        # pylint: disable=unused-argument
        """Gracefully captures SIGINT and SIGTERM to stop the reflector."""
        logger.info("Received termination signal %d. Shutting down gracefully...", signum)
        reflector.stop()
        sys.exit(0)

    # Trap Ctrl+C and standard system terminate signals
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        reflector.run()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Stopping...")
        reflector.stop()
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Fatal exception in main event loop: %s", str(e))
        if logger.isEnabledFor(logging.DEBUG):
            logging.exception(e)
        reflector.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
