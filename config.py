# corlor log setting

LOGGER_NAME = "my_logger"

import os
import sys

from utils import setup_logger

logger = setup_logger(LOGGER_NAME)

BASE_DIR = sys.path[0]
DATA_DIR = os.path.join(BASE_DIR, "data")
