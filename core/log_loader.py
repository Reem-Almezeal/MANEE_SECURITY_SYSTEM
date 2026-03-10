"""
Load and validate CSV log files for the MANEE' Security System.

This module provides the LogLoader class, which is responsible for
reading CSV log files, validating their format, and preparing the
data for further analysis.

"""
from colorama import Fore,init
import csv
import os

init(autoreset=True)


class LogLoader:
    """Load and validate CSV log files."""

    REQUIRED_COLUMNS = ["timestamp", "ip", "username", "event_type", "request"]

    def __init__(self, file_path: str):
        """Initialize the log loader.

        Args:
            file_path (str): Path to the CSV log file.
        """
        self.file_path = file_path

    def validate_file(self):
        """Validate the log file path and extension.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file is not a CSV file.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(Fore.RED +"Log file not found.")

        if not self.file_path.lower().endswith(".csv"):
            raise ValueError(Fore.RED +"Only CSV files are supported.")

    def validate_columns(self, fieldnames: list):
        """Validate that the CSV file contains all required columns.

        Args:
            fieldnames (list): List of column names from the CSV file.

        Raises:
            ValueError: If one or more required columns are missing.
        """
        missing_columns = []

        for column in self.REQUIRED_COLUMNS:
            if column not in fieldnames:
                missing_columns.append(column)

        if missing_columns:
            raise ValueError(Fore.RED +
                f"Missing required columns: {', '.join(missing_columns)}"
            )

    def load_logs(self):
        """Load log records from a CSV file.

        Returns:
            list[dict]: A list of log records.

        Raises:
            ValueError: If the file is empty or missing required columns.
            IOError: If an error occurs while reading the file.
        """
        self.validate_file()
        logs = []

        try:
            with open(self.file_path, "r", encoding="utf-8") as file:
                reader = csv.DictReader(file)

                if not reader.fieldnames:
                    raise ValueError(Fore.RED +"The CSV file is empty or has no header.")

                self.validate_columns(reader.fieldnames)

                for row in reader:
                    logs.append(row)

        except Exception as error:
            raise IOError(Fore.RED +f"Error reading log file: {error}")

        if not logs:
            raise ValueError(Fore.RED +"Log file is empty.")

        return logs