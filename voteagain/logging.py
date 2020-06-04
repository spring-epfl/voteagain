"""
Logging
"""

import logging
import sys


def create_logger(out, verbosity):
    """Create the logger"""
    logger = logging.getLogger("VoteAgain")
    logger.setLevel(verbosity)

    handler = logging.StreamHandler(out)
    handler.setLevel(verbosity)
    formatter = logging.Formatter("%(asctime)s,%(name)s,%(levelname)s:%(message)s")
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


LOGGER = create_logger(sys.stdout, logging.INFO)
