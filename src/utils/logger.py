"""
Logger configuration module using loguru
"""
import sys
import os
from loguru import logger
from config.settings import LOG_LEVEL, LOG_FILE

def setup_logger():
    """Configure loguru logger"""
    # Remove default logger
    logger.remove()
    
    # Ensure log directory exists
    log_dir = os.path.dirname(LOG_FILE)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Console output configuration
    logger.add(
        sys.stdout,
        level=LOG_LEVEL,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        colorize=True
    )
    
    # File output configuration
    logger.add(
        LOG_FILE,
        level=LOG_LEVEL,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="10 MB",
        retention="7 days",
        compression="zip"
    )
    
    return logger

def setup_apk_logger(apk_name: str):
    """Setup logger for specific APK analysis"""
    # Create APK-specific log file
    log_dir = os.path.dirname(LOG_FILE)
    apk_log_file = os.path.join(log_dir, f"{apk_name}_analysis.log")
    
    # Add APK-specific file logger
    logger.add(
        apk_log_file,
        level=LOG_LEVEL,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="10 MB",
        retention="7 days",
        compression="zip"
    )
    
    return logger

# Global logger instance
log = setup_logger()
