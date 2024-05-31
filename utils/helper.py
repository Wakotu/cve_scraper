import os

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


def get_query_dir(query: str) -> str:
    if states.nvd_mode:
        dir = os.path.join(config.DATA_DIR, "nvd", query)
    else:
        dir = os.path.join(config.DATA_DIR, "mitre", query)
    if not os.path.exists(dir):
        os.makedirs(dir)
    return dir
