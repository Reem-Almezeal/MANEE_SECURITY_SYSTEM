"""
Data Storage Module

This module handles reading and writing ticket data to the JSON
storage file used by the MANEE' Security System.
"""
from colorama import Fore,init
import json
import os

init(autoreset=True)

class DataStorage:
    """Handle ticket data persistence using a JSON file.

    Args:
        tickets_file (str): Relative path to the JSON file where
            tickets are stored.
    """

    def __init__(self, tickets_file: str):
        """Initialize the data storage service.

        Args:
            tickets_file (str): Path to the tickets JSON file.
        """
        project_dir = os.path.dirname(os.path.dirname(__file__))
        self.tickets_file = os.path.join(project_dir, tickets_file)

    def load_tickets(self):
        """Load tickets from the JSON storage file.

        Returns:
            list: List of stored tickets.

        Raises:
            ValueError: If the JSON file contains invalid data.
        """
        try:
            with open(self.tickets_file, "r", encoding="utf-8") as file:
                return json.load(file)

        except FileNotFoundError:
            return []

        except json.JSONDecodeError:
            raise ValueError(Fore.RED +"Tickets file contains invalid JSON.")

    def save_tickets(self, tickets):
        """Save tickets to the JSON storage file.

        Args:
            tickets (list): List of tickets to store.

        Raises:
            IOError: If an error occurs while saving the file.
        """
        try:
            with open(self.tickets_file, "w", encoding="utf-8") as file:
                json.dump(tickets, file, indent=4)

        except Exception as error:
            raise IOError(Fore.RED + f"Error saving tickets: {error}")