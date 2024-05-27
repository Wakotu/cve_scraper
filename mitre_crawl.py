import logging

import requests
from bs4 import BeautifulSoup
from termcolor import colored
from tqdm import tqdm

import config
import utils

logger = logging.getLogger(config.LOGGER_NAME)


def mitre_find_cve_ids(query: str) -> list[str]:
    """
    return: cve_id_list
    """
    cve_id_list = []
    base_url = "https://cve.mitre.org/cgi-bin/cvekey.cgi"
    params = {"keyword": query}
    resp = requests.get(base_url, params=params)
    assert resp.status_code == 200
    content = resp.text

    soup = BeautifulSoup(content, "html.parser")
    total_tag = soup.select("#CenterPane > div.smaller > b")[0]
    total_num = int(total_tag.text)
    cve_id_tags = soup.select("#TableWithRules > table > tr > td:nth-child(1) > a")
    # __import__("ipdb").set_trace()
    assert len(cve_id_tags) == total_num
    for tag in cve_id_tags:
        cve_id_list.append(tag.text)

    return cve_id_list


def main() -> None:
    # TODO: implement mitre scraper

    query = input(colored("Enter the keyword (e.g., Apache): ", "cyan"))
    logger.info("collecting cve ids...")
    cve_id_list = mitre_find_cve_ids(query)

    logger.info("start to collect each cve...")
    for cve_id in tqdm(cve_id_list):
        utils.fetch_cve_record(cve_id, query)
