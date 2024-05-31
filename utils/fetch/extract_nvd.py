# collect something

from dataclasses import dataclass

from bs4 import Tag


@dataclass
class CvssRec:
    # score: `score + level`
    score: str
    vector: str


def extract_desc(soup: Tag) -> str:
    selector = "#vulnDetailTableView > tbody > tr > td > div > div.col-lg-9.col-md-7.col-sm-12 > p"
    tag = soup.select(selector)[0]
    return tag.text


def extract_cvss(soup: Tag) -> CvssRec:
    # cvss related tag in nvd html has id attr, but we choose element-class hierarchy for robustness
    pass
