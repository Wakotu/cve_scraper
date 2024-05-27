import json
import logging
import os
from dataclasses import dataclass

import colorlog
import requests
from tqdm import tqdm

import config
import globals
import utils

logger = logging.getLogger(config.LOGGER_NAME)


@dataclass
class Distribution:
    LOW: int = 0
    MEDIUM: int = 0
    HIGH: int = 0
    CRITICAL: int = 0
    UNKNOWN: int = 0


@dataclass
class Report:
    total_num: int
    distri: Distribution
    score: int


def fetch_and_conclude(cve_id_list: list[str], query: str) -> None:

    logger.info("start to collect each cve...")
    for cve_id in tqdm(cve_id_list):
        utils.fetch_cve_record(cve_id, query)
    score = utils.gen_report(query)
    logger.info(f"hazard score for {query}: {score}")


def calc_score(distri: Distribution) -> int:
    return (
        distri.LOW * 2
        + distri.MEDIUM * 5
        + distri.HIGH * 8
        + distri.CRITICAL * 10
        + distri.UNKNOWN
    )


def object_to_dict(obj):
    """
    Recursively converts an object to a dictionary.
    """
    if isinstance(obj, dict):
        # If obj is already a dictionary, process each key-value pair recursively
        return {key: object_to_dict(value) for key, value in obj.items()}
    elif hasattr(obj, "__dict__"):
        # If obj is an instance of a class, get its __dict__ and process recursively
        return {key: object_to_dict(value) for key, value in obj.__dict__.items()}
    elif isinstance(obj, list):
        # If obj is a list, process each item recursively
        return [object_to_dict(item) for item in obj]
    elif isinstance(obj, tuple):
        # If obj is a tuple, process each item recursively
        return tuple(object_to_dict(item) for item in obj)
    elif isinstance(obj, set):
        # If obj is a set, process each item recursively
        return {object_to_dict(item) for item in obj}
    else:
        # If obj is not a dictionary, class instance, list, tuple, or set, return it as-is
        return obj


def get_query_dir(query: str) -> str:
    if globals.nvd_mode:
        dir = os.path.join(config.DATA_DIR, "nvd", query)
    else:
        dir = os.path.join(config.DATA_DIR, "mitre", query)
    if not os.path.exists(dir):
        os.makedirs(dir)
    return dir


def collect_info(dir: str) -> Report:
    try:
        # List all entries in the directory
        entries = os.listdir(dir)
        # Count the number of entries
        num_entries = 0
        distri = Distribution()
        for entry in entries:
            if not entry.startswith("CVE"):
                continue
            num_entries += 1

            # collect low, medium and high
            # how to handle multi metrics? apply the newest metric verion
            filename = os.path.join(dir, entry)
            with open(filename, "r", encoding="utf-8") as f:
                rec = json.load(f)
            try:
                metrics = rec["containers"]["cna"]["metrics"]
            except KeyError:
                distri.UNKNOWN += 1
                continue

            assert isinstance(metrics, list)
            if len(metrics) != 1:
                distri.UNKNOWN += 1
                continue

            metric = metrics[0]
            assert isinstance(metric, dict)

            newest_key = ""
            for key in metric.keys():
                if newest_key < key:
                    newest_key = key
            info = metric[newest_key]
            try:
                severity = info["baseSeverity"]
                val = getattr(distri, severity) + 1
                setattr(distri, severity, val)
            except KeyError:
                distri.UNKNOWN += 1
        score = calc_score(distri)
        return Report(num_entries, distri, score)

    except FileNotFoundError:
        print(f"Error: The directory '{dir}' does not exist.")
        exit(1)
    except PermissionError:
        print(f"Error: Permission denied to access '{dir}'.")
        exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        exit(1)


def gen_report(query: str) -> int:
    """
    collect statistics and write to report.json and return hazard score
    """
    query_dir = get_query_dir(query)
    filename = os.path.join(query_dir, "report.json")
    # collect information
    report = collect_info(query_dir)
    score = report.score
    with open(filename, "w", encoding="utf-8") as f:
        report_dict = object_to_dict(report)
        json.dump(report_dict, f, indent=4)
    return score


def fetch_cve_record(cve_id: str, query: str) -> None:
    """
    fetch cve record and save it to local disk
    """
    base_url = "https://cveawg.mitre.org/api/cve/"
    resp = requests.get(base_url + cve_id)
    res = resp.json()

    # concatenate filename, dir architecture based on different mode(source)
    dir = get_query_dir(query)
    filename = os.path.join(dir, f"{cve_id}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=4)


def setup_logger(logger_name: str) -> logging.Logger:
    # Create a logger object
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # Define log colors and format
    formatter = colorlog.ColoredFormatter(
        "%(log_color)s[%(levelname)s]%(reset)s - %(blue)s%(asctime)s%(reset)s - %(message)s",
        datefmt=None,
        reset=True,
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
    )

    # Set formatter for the console handler
    console_handler.setFormatter(formatter)

    # Add the console handler to the logger
    logger.addHandler(console_handler)

    return logger
