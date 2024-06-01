import json
import os

import requests
from bs4 import BeautifulSoup

import states
from utils.fetch.extract_nvd import (
    extract_cvss,
    extract_cwe,
    extract_date,
    extract_desc,
)

from ..helper import get_query_dir


def fetch_cve_record_mitre(cve_id: str) -> dict:
    """
    fetch cve under mitre mode
    """

    base_url = "https://cveawg.mitre.org/api/cve/"
    resp = requests.get(base_url + cve_id)
    res = resp.json()
    return res


def fetch_cve_record_nvd(cve_id: str) -> dict:
    if states.debug_mode:
        __import__("ipdb").set_trace()
    base_url = "https://nvd.nist.gov/vuln/detail/"
    url = base_url + cve_id
    resp = requests.get(url)
    content = resp.text
    soup = BeautifulSoup(content, "html.parser")

    desc = extract_desc(soup)
    cvss = extract_cvss(soup)
    date = extract_date(soup)
    cwe = extract_cwe(soup)

    # integrate all collected record to a dict -> specify `key` string
    rec = {
        "desc": desc,
        "cvss": vars(cvss),
        "date": vars(date),
        "cwe": vars(cwe),
    }
    return rec


def fetch_cve_record(cve_id: str, query: str) -> None:
    """
    fetch cve record and save it to local disk
    """
    if states.nvd_mode:
        rec = fetch_cve_record_nvd(cve_id)
    else:
        rec = fetch_cve_record_mitre(cve_id)
    dir = get_query_dir(query)
    filename = os.path.join(dir, f"{cve_id}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=4)
