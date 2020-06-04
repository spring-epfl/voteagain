"""
Parser functions.
"""

# Pythn standard library
import csv

from pathlib import Path
from typing import List

# Local files
from .logging import LOGGER


def parse_arg_list_int(list_int):
    """Parse an argument as a list of integers."""

    try:
        params = [int(param) for param in list_int.split(",")]
    except:
        raise AttributeError()

    return params


def parse_arg_list_float(list_float):
    """Parse an argument as a list of floats."""

    try:
        params = [float(param) for param in list_float.split(",")]
    except:
        raise AttributeError()

    return params


def ensures_dir_exists(dirpath: Path) -> None:
    """Ensures a directory exists."""

    if dirpath.exists():
        if dirpath.is_dir():
            return
        else:
            raise AttributeError(
                "File {} already exists and is not a directory.".format(dirpath)
            )
    else:
        dirpath.mkdir(parents=True)


def ensures_csv_exists(filepath: Path, title: List[str]) -> None:
    """Write the title of a CSV of"""

    if filepath.exists():
        LOGGER.info("Append data to file %s.", filepath)
    else:
        LOGGER.info("File %s created.", filepath)
        with filepath.open(mode="w", newline="") as file_fd:
            filewriter = csv.writer(
                file_fd, delimiter=",", quotechar="|", quoting=csv.QUOTE_MINIMAL
            )
            filewriter.writerow(title)
