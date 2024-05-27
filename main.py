import argparse
import json
import logging
import os

import requests
from bs4 import BeautifulSoup
from termcolor import colored
from tqdm import tqdm

import config

# global vars
debug_mode = False
nvd_mode = False
logger = logging.getLogger(config.LOGGER_NAME)


def parse_args() -> None:
    """
    a helper function to parse cmd args and store to global vars
    """
    parser = argparse.ArgumentParser(description="CVE Scraper")
    parser.add_argument("-d", "--debug", action="store_true", help="debug mode ")
    parser.add_argument(
        "-n", "--nvd", action="store_true", help="fetch from nvd or mitre website"
    )
    args = parser.parse_args()
    global debug_mode, nvd_mode
    debug_mode = args.debug
    nvd_mode = args.nvd


def fetch_cve_record(cve_id: str, query: str) -> None:
    """
    fetch cve record and save it to local disk
    """
    base_url = "https://cveawg.mitre.org/api/cve/"
    resp = requests.get(base_url + cve_id)
    res = resp.json()

    # concatenate filename, dir architecture based on different mode(source)
    if nvd_mode:
        dir = os.path.join(config.DATA_DIR, "nvd", query)
    else:
        dir = os.path.join(config.DATA_DIR, "mitre", query)
    if not os.path.exists(dir):
        os.makedirs(dir)
    filename = os.path.join(dir, f"{cve_id}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=4)


def total_end_extract(soup, total_num: int | None, cpe: bool) -> tuple[int, int]:

    if cpe:
        total_sel = (
            "#body-section > div:nth-child(2) > div.row > div:nth-child(2) > strong"
        )
        end_sel = "#body-section > div:nth-child(2) > div.row > div:nth-child(2) > span > strong:nth-child(2)"
    else:
        total_sel = "#vulnerability-search-results-div > div.row > div.col-sm-12.col-lg-3 > strong"
        end_sel = "#results-numbers-panel > strong:nth-child(2)"
    if total_num is None:
        num_tag = soup.select(total_sel)[0]
        assert num_tag is not None
        total_num = int(num_tag.text)

    num_tag = soup.select(end_sel)[0]
    assert num_tag is not None
    end_index = int(num_tag.text) - 1

    return total_num, end_index


def find_cpes_part(
    component: str, version: str, start_index: int, total_num: int | None
) -> tuple[list[str], int, int]:
    """
    returns cves_links, next_start_index, total_num
    """

    base_domain = "https://nvd.nist.gov"
    base_url = "https://nvd.nist.gov/products/cpe/search/results"
    params = {
        "namingFormat": "2.3",
        "keyword": f"{component} {version}",
        "startIndex": start_index,
    }
    response = requests.get(base_url, params=params)
    content = response.text
    soup = BeautifulSoup(content, "html.parser")

    total_num, end_index = total_end_extract(soup, total_num, True)

    # extract cves_links
    cves_links = []
    link_tags = soup.select(
        "#cpeSearchResultTBody > tr > td > div:nth-child(1) > div > a"
    )
    assert (
        len(link_tags) == end_index - start_index + 1
    ), "failed to extract cve links of correct number"
    for link_tag in link_tags:
        link = link_tag.get("href")
        assert isinstance(link, str), "failed to collect CVE link as string"
        cves_links.append(base_domain + link)

    return cves_links, end_index + 1, total_num


def find_cpes(component: str, version: str) -> list[str]:
    start_index = 0
    total_num = None
    total_links = []

    while total_num is None or start_index < total_num:
        cves_links, start_index, total_num = find_cpes_part(
            component, version, start_index, total_num
        )
        total_links.extend(cves_links)
    assert (
        len(total_links) == total_num
    ), f"total link num mismatched: {len(total_links)}/{total_num}"
    return total_links


def find_cves_part(
    url: str, start_index: int, total_num: int | None
) -> tuple[list[str], int, int]:
    """
    return: cve_id_list, next_start_index, total_num
    """
    params = {"startIndex": start_index}
    resp = requests.get(url=url, params=params)
    assert (
        resp.status_code == 200
    ), f"failed to access: {url}, with params startIndex = {start_index}"
    content = resp.text
    soup = BeautifulSoup(content, "html.parser")

    total_num, end_index = total_end_extract(soup, total_num, False)

    cve_ids = []
    cve_id_tags = soup.select("#row > table > tbody > tr > th > strong > a")
    assert (
        len(cve_id_tags) == end_index - start_index + 1
    ), "failed to extract cve ids with correct number"
    for tag in cve_id_tags:
        cve_ids.append(tag.text)

    return cve_ids, end_index + 1, total_num


def find_cves(cpe_search_link: str) -> list[str]:
    total_cve_ids = set()
    start_index = 0
    total_num = None

    if debug_mode:
        __import__("ipdb").set_trace()

    while total_num is None or start_index < total_num:
        cve_ids, start_index, total_num = find_cves_part(
            cpe_search_link, start_index, total_num
        )
        total_cve_ids.update(cve_ids)

    assert (
        len(total_cve_ids) == total_num
    ), "cve id mismatched in url: {cpe_search_link}"
    return list(total_cve_ids)


def crawl_nvd() -> None:
    # find cpe and corresponding cves

    component = input(colored("Enter the component (e.g., Apache): ", "cyan"))
    version = input(colored("Enter the version (e.g., 4.2.1): ", "cyan"))

    logger.info("searching for cpes...")
    cves_links = find_cpes(component, version)

    # collect cve ids
    logger.info("collecting cve ids...")
    total_cve_ids = set()
    for cves_link in tqdm(cves_links):
        cve_ids = find_cves(cves_link)
        total_cve_ids.update(cve_ids)
    total_cve_ids = list(total_cve_ids)

    # fetch each
    logger.info("start to collect each cve...")
    for cve_id in tqdm(total_cve_ids):
        fetch_cve_record(cve_id, f"{component}:{version}")


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


def crawl_mitre() -> None:
    # TODO: implement mitre scraper

    query = input(colored("Enter the keyword (e.g., Apache): ", "cyan"))
    logger.info("collecting cve ids...")
    cve_id_list = mitre_find_cve_ids(query)

    logger.info("start to collect each cve...")
    for cve_id in tqdm(cve_id_list):
        fetch_cve_record(cve_id, query)
    raise NotImplementedError()


if __name__ == "__main__":
    parse_args()
    if nvd_mode:
        crawl_nvd()
    else:
        crawl_mitre()
