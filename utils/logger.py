"""
Logging utilities for AutoReconX
Provides structured logging with file and console outputs.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored console output."""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA + Style.BRIGHT
    }
    
    def format(self, record):
        # Add color to levelname
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        
        return super().format(record)


def setup_logging(log_file=None, level=logging.INFO, console_output=True):
    """
    Setup logging configuration for AutoReconX.
    
    Args:
        log_file (Path): Path to log file
        level (int): Logging level
        console_output (bool): Enable console output
    """
    # Create root logger
    logger = logging.getLogger()
    logger.setLevel(level)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Add file handler if log_file is provided
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    # Add console handler if enabled
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    return logger


def get_module_logger(name):
    """Get a logger for a specific module."""
    return logging.getLogger(name)


class ProgressLogger:
    """Logger with progress tracking capabilities."""
    
    def __init__(self, name, total_steps=None):
        self.logger = get_module_logger(name)
        self.total_steps = total_steps
        self.current_step = 0
        self.start_time = datetime.now()
    
    def step(self, message=""):
        """Log a step completion."""
        self.current_step += 1
        if self.total_steps:
            progress = (self.current_step / self.total_steps) * 100
            self.logger.info(f"Step {self.current_step}/{self.total_steps} ({progress:.1f}%): {message}")
        else:
            self.logger.info(f"Step {self.current_step}: {message}")
    
    def info(self, message):
        """Log an info message."""
        self.logger.info(message)
    
    def warning(self, message):
        """Log a warning message."""
        self.logger.warning(message)
    
    def error(self, message):
        """Log an error message."""
        self.logger.error(message)
    
    def debug(self, message):
        """Log a debug message."""
        self.logger.debug(message)
    
    def finish(self, message="Completed"):
        """Log completion with elapsed time."""
        elapsed = datetime.now() - self.start_time
        self.logger.info(f"{message} (Total time: {elapsed})")


if __name__ == "__main__":
    # Test the logging setup
    setup_logging(Path("test.log"), logging.DEBUG)
    
    logger = get_module_logger("test")
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    # Test progress logger
    progress = ProgressLogger("test_progress", 5)
    for i in range(5):
        progress.step(f"Processing item {i+1}")
    progress.finish() 