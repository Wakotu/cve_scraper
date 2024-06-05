import json
import os
from dataclasses import dataclass

import states

from .helper import get_query_dir, object_to_dict

SEVERITY_SCORE = {"UNKNOWN": 1, "LOW": 2, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
TIME_FACTOR = {
    "DISTANT": 0.1,
    "INTM": 0.3,
    "RECENT": 1,
}


# TODO: need to add cwe statistics for nvd mode


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


def calc_score(sev: str, time: str) -> float:
    return SEVERITY_SCORE.get(sev, 0) * TIME_FACTOR.get(time, 0)


def add_one(obj, attr: str) -> None:
    val = getattr(obj, attr) + 1
    setattr(obj, attr, val)


def collect_severity(rec: dict, sev_dist: SeverDist, entry: str = "") -> str:
    """
    returns the severity string and update distribution
    """

    if states.nvd_mode:
        sev = "UNKNOWN"
        cvss_list = rec["cvss"]
        for cvss in cvss_list:
            score = cvss["score"]
            assert isinstance(score, str)
            score = score.strip()
            if score == "N/A":
                continue
            sev = score.split()[-1]
            break

        add_one(sev_dist, sev)
        return sev

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
        add_one(sev_dist, severity)
        return severity
    except KeyError:
        sev_dist.UNKNOWN += 1
        return "UNKNOWN"


def collect_time(rec: dict, time_dist: TimeDist) -> str:
    """
    returns time str and update distribution
    """
    # collect year attribute
    if states.nvd_mode:
        date_str = rec["date"]["published"]
        assert isinstance(date_str, str)
        year = date_str.split("/")[-1]
    else:
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
    add_one(time_dist, time)
    return time


# TODO split nvd utils and mitre utils
def collect_info(dir: str) -> Report:
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

        severity = collect_severity(rec, sev_dist)
        try:
            time = collect_time(rec, time_dist)
        except KeyError as e:
            assert False, f"error in time info collecting of {entry}: {e}"
        score += calc_score(severity, time)

    return Report(num_entries, sev_dist, time_dist, score)


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
