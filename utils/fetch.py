import json
import os

import requests
from bs4 import BeautifulSoup

import states

from .helper import get_query_dir


def fetch_cve_record_mitre(cve_id: str, query: str) -> None:
    """
    fetch cve under mitre mode
    """

    base_url = "https://cveawg.mitre.org/api/cve/"
    resp = requests.get(base_url + cve_id)
    res = resp.json()

    # concatenate filename, dir architecture based on different mode(source)
    dir = get_query_dir(query)
    filename = os.path.join(dir, f"{cve_id}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=4)


def fetch_cve_record_nvd(cve_id: str, query: str) -> None:
    base_url = "https://nvd.nist.gov/vuln/detail/"
    url = base_url + cve_id
    resp = requests.get(url)
    content = resp.text
    soup = BeautifulSoup(content, "html.parser")


def fetch_cve_record(cve_id: str, query: str) -> None:
    """
    fetch cve record and save it to local disk
    """
    if states.nvd_mode:
        fetch_cve_record_nvd(cve_id, query)
    else:
        fetch_cve_record_mitre(cve_id, query)
