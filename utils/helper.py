import os

import requests
from bs4 import BeautifulSoup, Tag

import config
import states


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


def get_soup(url: str) -> BeautifulSoup:
    """
    get soup object based on url
    """
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    return soup


def get_query_dir(query: str) -> str:
    if states.nvd_mode:
        dir = os.path.join(config.DATA_DIR, "nvd", query)
    else:
        dir = os.path.join(config.DATA_DIR, "mitre", query)
    if not os.path.exists(dir):
        os.makedirs(dir)
    return dir


# debug helper


def show_tag(root: Tag, depth: int) -> None:
    def show_tag_recur(root: Tag, depth: int, cur: int) -> None:
        if cur > depth:
            return
        indent = "  "
        print(f"{indent * cur}{root.name}")

        for child in root.children:
            if not isinstance(child, Tag):
                continue
            show_tag_recur(child, depth, cur + 1)

    show_tag_recur(root, depth, 0)
