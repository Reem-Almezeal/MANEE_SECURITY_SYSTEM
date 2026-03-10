"""
Log Analyzer Module

This module analyzes log records and extracts useful statistics
such as total number of logs, most common IP addresses, and
most frequent event types.
"""
from colorama import Fore,init
from collections import Counter


init(autoreset=True)

class LogAnalyzer:
    """Analyze log records and generate summary statistics.

    Args:
        logs (list): List of dictionaries representing log entries.
    """

    def __init__(self, logs: list):
        """Initialize the log analyzer.

        Args:
            logs (list): List of log dictionaries.
        """
        self.logs = logs

    def count_total_logs(self):
        """Count the total number of log entries.

        Returns:
            int: Total number of log records.
        """
        return len(self.logs)

    def top_ips(self):
        """Find the most frequent IP addresses in the logs.

        Returns:
            list[tuple]: Top 3 IP addresses and their occurrence counts.
        """
        ip_list = []

        for log in self.logs:
            if "ip" in log and log["ip"]:
                ip_list.append(log["ip"])

        return Counter(ip_list).most_common(3)

    def top_events(self):
        """Find the most common event types in the logs.

        Returns:
            list[tuple]: Top 3 event types and their occurrence counts.
        """
        event_list = []

        for log in self.logs:
            if "event_type" in log and log["event_type"]:
                event_list.append(log["event_type"])

        return Counter(event_list).most_common(3)

    def analyze_summary(self):
        """Generate a summary of the analyzed log data.

        Returns:
            dict: Summary containing:
                - total_logs
                - top_ips
                - top_events
        """
        return {
            "total_logs": self.count_total_logs(),
            "top_ips": self.top_ips(),
            "top_events": self.top_events()
        }