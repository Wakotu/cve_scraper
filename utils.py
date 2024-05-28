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

# NOTE: distribution type should be modeled as enum + dict


@dataclass
class SeverDist:
    LOW: int = 0
    MEDIUM: int = 0
    HIGH: int = 0
    CRITICAL: int = 0
    UNKNOWN: int = 0


@dataclass
class TimeDist:
    # 90 - 10
    DISTANT: int = 0
    # 10 - 20
    INTM: int = 0
    # 20 - now
    RECENT: int = 0


@dataclass
class Report:
    total_num: int
    sev_dist: SeverDist
    time_dist: TimeDist
    score: float


SEVERITY_SCORE = {"UNKNOWN": 1, "LOW": 2, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
TIME_FACTOR = {
    "DISTANT": 0.1,
    "INTM": 0.3,
    "RECENT": 1,
}


def get_dist_str(dist_dict: dict, prompt: str) -> str:
    log_str = prompt
    first = True
    for key, val in dist_dict.items():
        if first:
            first = False
        else:
            log_str += ", "
        log_str += f"{key}: {val}"
    return log_str


def fetch_and_conclude(cve_id_list: list[str], query: str) -> None:

    logger.info("start to collect each cve...")
    for cve_id in tqdm(cve_id_list):
        utils.fetch_cve_record(cve_id, query)
    report = utils.gen_report(query)

    # report logging
    logger.info(f"report for {query}")
    logger.info(f"total cve number: {report.total_num}, Distribution follows:")

    sev_dict = object_to_dict(report.sev_dist)
    assert isinstance(sev_dict, dict)
    logger.info(get_dist_str(sev_dict, "severity Distribution"))

    time_dict = object_to_dict(report.time_dist)
    assert isinstance(time_dict, dict)
    logger.info(get_dist_str(time_dict, "time Distribution"))

    logger.info(f"hazard score: {report.score}")


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


def calc_score(sev: str, time: str) -> float:
    return SEVERITY_SCORE.get(sev, 0) * TIME_FACTOR.get(time, 0)


def collect_severity(rec: dict, sev_dist: SeverDist, entry: str = "") -> str:
    """
    returns the severity string
    """

    try:
        metrics = rec["containers"]["cna"]["metrics"]
    except KeyError:
        sev_dist.UNKNOWN += 1
        return "UNKNOWN"

    assert isinstance(metrics, list)
    if len(metrics) != 1:
        sev_dist.UNKNOWN += 1
        return "UNKNOWN"

    metric = metrics[0]
    assert isinstance(metric, dict)

    cvss_key = ""
    for key in metric.keys():
        if not key.startswith("cvss"):
            continue
        cvss_key = key
        break
    if cvss_key == "":
        sev_dist.UNKNOWN += 1
        return "UNKNOWN"

    info = metric[cvss_key]
    assert isinstance(info, dict)

    try:
        severity = info["baseSeverity"]
        assert isinstance(severity, str)
        val = getattr(sev_dist, severity) + 1
        setattr(sev_dist, severity, val)
        return severity
    except KeyError:
        sev_dist.UNKNOWN += 1
        return "UNKNOWN"


def collect_time(rec: dict, time_dist: TimeDist) -> str:
    try:
        date_str = rec["cveMetadata"]["datePublished"]
    except KeyError:
        date_str = rec["cveMetadata"]["dateUpdated"]

    assert isinstance(date_str, str)
    year = date_str.split("-")[0]
    if year <= "2010":
        time = "DISTANT"
    elif year <= "2020":
        time = "INTM"
    else:
        time = "RECENT"
    val = getattr(time_dist, time) + 1
    setattr(time_dist, time, val)
    return time


def collect_info(dir: str) -> Report:
    try:
        # List all entries in the directory
        entries = os.listdir(dir)
        # Count the number of entries
        num_entries = 0
        sev_dist = SeverDist()
        time_dist = TimeDist()
        score = 0
        for entry in entries:
            if not entry.startswith("CVE"):
                continue
            num_entries += 1

            filename = os.path.join(dir, entry)
            with open(filename, "r", encoding="utf-8") as f:
                rec = json.load(f)

            if globals.debug_mode:
                severity = collect_severity(rec, sev_dist, entry)
            else:
                severity = collect_severity(rec, sev_dist)
            try:
                time = collect_time(rec, time_dist)
            except KeyError as e:
                assert False, f"error in time info collecting of {entry}: {e}"
            score += calc_score(severity, time)

        return Report(num_entries, sev_dist, time_dist, score)

    except FileNotFoundError:
        print(f"Error: The directory '{dir}' does not exist.")
        exit(1)
    except PermissionError:
        print(f"Error: Permission denied to access '{dir}'.")
        exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        exit(1)


def gen_report(query: str) -> Report:
    """
    collect report from cve records, return report and write to `report.json`
    """
    query_dir = get_query_dir(query)
    filename = os.path.join(query_dir, "report.json")
    # collect information
    report = collect_info(query_dir)
    with open(filename, "w", encoding="utf-8") as f:
        report_dict = object_to_dict(report)
        json.dump(report_dict, f, indent=4)
    return report


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
