# src/utils/logger.py
import logging
from src.utils.config_loader import load_config
config = load_config()
def setup_logger(name, log_file, level=logging.INFO):
    if config["logging"]["enabled"]:
        formatter = logging.Formatter('%(asctime)s -%(name)s - %(levelname)s - %(message)s')
        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)

        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.addHandler(handler)

        return logger
    else:
        print("logging disabled in config")
