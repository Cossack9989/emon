import sys
from loguru import logger

logger.remove()
logger.add(
    sys.stdout,
    level="INFO",
    colorize=True,
    format="<blue>{time:HH:mm:ss}</blue> <lvl>{level}</lvl> {message}"
)