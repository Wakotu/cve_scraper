# collect something
import re
from dataclasses import dataclass

from bs4 import BeautifulSoup

import states

from ..helper import get_soup


@dataclass
class CvssRec:
    # score: `score + level`
    version: str
    score: str
    vector: str


@dataclass
class DateRec:
    published: str
    last_modified: str


@dataclass
class CweRec:
    id: str
    name: str
    desc: str


def text_repr(s: str) -> str:
    return re.sub(r"\s+", " ", s)


def extract_desc(soup: BeautifulSoup) -> str:
    selector = "#vulnDetailTableView > tbody > tr > td > div > div.col-lg-9.col-md-7.col-sm-12 > p"
    try:
        tag = soup.select(selector)[0]
    except IndexError:
        tag = soup.select(selector.replace(" > tbody", ""))[0]
    return text_repr(tag.text)


def extract_cvss(soup: BeautifulSoup) -> list[CvssRec]:
    # find the cvss panel
    version_tags = soup.select("div#cvssVulnDetailBtn > button.btn")
    score_tags = soup.select(
        "div#vulnCvssPanel > div > div:nth-of-type(1) > div:nth-of-type(2) > span > span > a"
    )
    vector_tags = soup.select(
        "div#vulnCvssPanel> div > div:nth-of-type(1) > div:nth-of-type(3) > span > span"
    )
    assert len(version_tags) == len(score_tags) == len(vector_tags) == 3

    res = []
    for ind in range(3):
        res.append(
            CvssRec(
                text_repr(version_tags[ind].text),
                text_repr(score_tags[ind].text),
                text_repr(vector_tags[ind].text),
            )
        )
    return res


def extract_date(soup: BeautifulSoup) -> DateRec:
    pub_tag = soup.select(
        "#vulnDetailTableView > tr > td > div > div.col-lg-3.col-md-5.col-sm-12 > div > span:nth-child(8)"
    )[0]
    mod_tag = soup.select(
        "#vulnDetailTableView > tr > td > div > div.col-lg-3.col-md-5.col-sm-12 > div > span:nth-child(12)"
    )[0]
    return DateRec(text_repr(pub_tag.text), text_repr(mod_tag.text))


def get_cwe_desc(url: str) -> str:
    """
    fetch cwe description based on link
    """
    soup = get_soup(url)
    desc_tags = soup.select("div#Description > div > div > div")
    if len(desc_tags) == 0:
        return "not found"
    return desc_tags[0].text


def extract_cwe(soup: BeautifulSoup, entry_url: str = "") -> list[CweRec]:
    id_tags = soup.select(
        "#vulnTechnicalDetailsDiv > table > tbody > tr > td:nth-child(1) > a"
    )
    name_tags = soup.select(
        "#vulnTechnicalDetailsDiv > table > tbody > tr > td:nth-child(2)"
    )
    assert len(id_tags) == len(
        name_tags
    ), f"unequal cwe id and names in url: {entry_url}"
    num_cwe = len(id_tags)
    res = []
    for ind in range(num_cwe):
        id = id_tags[ind].text
        id = text_repr(id)
        name = name_tags[ind].text
        name = text_repr(name)
        if id_tags[ind].name != "a":
            desc = "not found"
        else:
            url = id_tags[ind]["href"]
            assert isinstance(url, str)
            desc = get_cwe_desc(url)
            desc = text_repr(desc)
        res.append(CweRec(id, name, desc))

    return res


# TODO:  affected products extraction to be finished
