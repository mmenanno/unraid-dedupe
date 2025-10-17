#!/usr/bin/env python3
"""
Shared logging configuration for all modules
Ensures consistent logging setup across the application
"""

import logging


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger configured to work with Gunicorn

    When running under Gunicorn:
    - Uses Gunicorn's error log handlers (writes to error.log)
    - Also adds StreamHandler for Docker logs (stdout/stderr)

    When running standalone:
    - Uses basic logging configuration

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Only configure if not already configured
    if logger.handlers:
        return logger

    try:
        # Try to use Gunicorn's logger
        gunicorn_logger = logging.getLogger('gunicorn.error')
        if gunicorn_logger.handlers:
            # Copy Gunicorn's handlers
            logger.handlers = gunicorn_logger.handlers[:]

            # Also add StreamHandler for Docker logs (stdout/stderr)
            if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
                stream_handler = logging.StreamHandler()
                stream_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                ))
                logger.addHandler(stream_handler)

            logger.setLevel(gunicorn_logger.level)
            return logger
    except (AttributeError, KeyError):
        pass

    # Fallback: use basic configuration
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    logger.setLevel(logging.INFO)
    return logger

