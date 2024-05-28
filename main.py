import argparse

import config
import globals
import mitre_crawl
import nvd_crawl

# global vars
globals.init()

from utils import setup_logger

logger = setup_logger(config.LOGGER_NAME)


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
    globals.debug_mode = args.debug
    globals.nvd_mode = args.nvd


if __name__ == "__main__":
    parse_args()
    if globals.nvd_mode:
        nvd_crawl.main()
    else:
        mitre_crawl.main()
