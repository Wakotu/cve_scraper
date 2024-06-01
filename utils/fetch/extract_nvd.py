# collect something

from dataclasses import dataclass

from bs4 import BeautifulSoup

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


def extract_desc(soup: BeautifulSoup) -> str:
    selector = "#vulnDetailTableView > tbody > tr > td > div > div.col-lg-9.col-md-7.col-sm-12 > p"
    tag = soup.select(selector)[0]
    return tag.text


def extract_cvss(soup: BeautifulSoup) -> list[CvssRec]:
    # find the cvss panel
    version_tags = soup.select("div#cvssVulnDetailBtn > button.btn")
    score_tags = soup.select(
        "div#vulnCvssPanel > div > div:nth-child(1) > div:nth-child(2) > span > span > a"
    )
    vector_tags = soup.select(
        "div#vulnCvssPanel> div > div:nth-child(1) > div:nth-child(3) > span > span"
    )
    assert len(version_tags) == len(score_tags) == len(vector_tags) == 3

    res = []
    for ind in range(3):
        res.append(
            CvssRec(version_tags[ind].text, score_tags[ind].text, vector_tags[ind].text)
        )
    return res


def extract_date(soup: BeautifulSoup) -> DateRec:
    pub_tag = soup.select(
        "#vulnDetailTableView > tbody > tr > td > div > div.col-lg-3.col-md-5.col-sm-12 > div > span:nth-child(8)"
    )[0]
    mod_tag = soup.select(
        "#vulnDetailTableView > tbody > tr > td > div > div.col-lg-3.col-md-5.col-sm-12 > div > span:nth-child(12)"
    )[0]
    return DateRec(pub_tag.text, mod_tag.text)


def get_cwe_desc(url: str) -> str:
    """
    fetch cwe description based on link
    """
    soup = get_soup(url)
    desc_tags = soup.select("div#Description > div > div > div")
    if len(desc_tags) == 0:
        return "not found"
    return desc_tags[0].text


def extract_cwe(soup: BeautifulSoup) -> list[CweRec]:
    id_tags = soup.select(
        "#vulnTechnicalDetailsDiv > table > tbody > tr > td:nth-child(1) > a"
    )
    name_tags = soup.select(
        "#vulnTechnicalDetailsDiv > table > tbody > tr > td:nth-child(2)"
    )
    assert len(id_tags) == len(name_tags)
    num_cwe = len(id_tags)
    res = []
    for ind in range(num_cwe):
        id = id_tags[ind].text
        name = name_tags[ind].text
        if id_tags[ind].tag != "a":
            desc = "not found"
        else:
            url = id_tags[ind]["href"]
            assert isinstance(url, str)
            desc = get_cwe_desc(url)
        res.append(CweRec(id, name, desc))

    return res


# TODO:  affected products extraction to be finished
