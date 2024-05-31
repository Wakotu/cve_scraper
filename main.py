import argparse

import vars

import config
import mitre_crawl
import nvd_crawl

# global vars
vars.init()

import utils

logger = utils.setup_logger(config.LOGGER_NAME)


def parse_args() -> argparse.Namespace:
    """
    parse args from command line and returns
    """
    parser = argparse.ArgumentParser(description="CVE Scraper")
    parser.add_argument("-d", "--debug", action="store_true", help="debug mode ")
    parser.add_argument(
        "-n", "--nvd", action="store_true", help="fetch from nvd or mitre website"
    )
    parser.add_argument(
        "-o", "--overview", action="store_true", help="get overview report"
    )
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()
    # handle args and modify global states
    vars.debug_mode = args.debug
    vars.nvd_mode = args.nvd

    if args.overview:
        utils.queries_overview()
        exit(0)

    if vars.nvd_mode:
        nvd_crawl.main()
    else:
        mitre_crawl.main()
