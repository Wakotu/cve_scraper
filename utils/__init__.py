import json
import logging
import os
from json import encoder
from typing import assert_never

import colorlog
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

import config
import states

from .fetch import fetch_cve_record
from .helper import object_to_dict
from .plot import plot_overview
from .report import gen_report

logger = logging.getLogger(config.LOGGER_NAME)

# NOTE: distribution type should be modeled as enum + dict


def queries_overview() -> None:
    """
    collect reports from local disk and log the information
    """
    if states.nvd_mode:
        dir = os.path.join(config.DATA_DIR, "nvd")
    else:
        dir = os.path.join(config.DATA_DIR, "mitre")

    queries = os.listdir(dir)
    logger.info(f"{len(queries)} queries collected.")

    # handle each query
    rep_data = {"total_num": [], "score": []}
    for qr in queries:
        report_file = os.path.join(dir, qr, "report.json")
        has_report = True
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                rep = json.load(f, parse_float=lambda x: round(float(x), 2))
        except FileNotFoundError:
            logger.warning(f"failed to find report of query {qr}")
            total_num = 0
            score = 0
            has_report = False

        if has_report:
            try:
                total_num = rep["total_num"]
                score = rep["score"]
            except KeyError:
                assert False, f"failed to collect score and num info from {qr}"

        rep_data["total_num"].append(total_num)
        rep_data["score"].append(score)

        logger.info(f"[{qr}] total_num: {total_num}, score: {score}")

    plot_overview(queries, rep_data)


def get_dist_str(dist_dict: dict, prompt: str) -> str:
    log_str = prompt + " "
    first = True
    for key, val in dist_dict.items():
        if first:
            first = False
        else:
            log_str += ", "
        log_str += f"{key}: {val}"
    return log_str


def fetch_and_conclude(cve_id_list: list[str], query: str) -> None:
    # abort on empty cve list
    if len(cve_id_list) == 0:
        logger.warning("No cve records found")
        return
    logger.info("start to collect each cve...")
    for cve_id in tqdm(cve_id_list):
        fetch_cve_record(cve_id, query)

    report = gen_report(query)
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
