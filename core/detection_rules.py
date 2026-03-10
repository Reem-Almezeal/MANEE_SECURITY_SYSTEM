"""
Detection Rules Module

This module contains security detection rules used to identify
suspicious activities in log data such as brute force attacks,
SQL injection attempts, suspicious RDP activity, malicious
PowerShell commands, and suspicious file downloads.
"""
from colorama import Fore,init


init(autoreset=True)

class DetectionRules:
    """Apply security detection rules to log records.

    Args:
        logs (list): List of log dictionaries to analyze.
    """

    def __init__(self, logs: list):
        """Initialize detection rules with log data.

        Args:
            logs (list): List of log records.
        """
        self.logs = logs

    def detect_sql_injection(self):
        """Detect possible SQL injection attempts.

        Returns:
            list: List of SQL injection alerts.
        """
        alerts = []
        suspicious_patterns = ["' or 1=1", "union select", "drop table", "--"]

        for log in self.logs:
            request = log.get("request", "").lower()

            for pattern in suspicious_patterns:
                if pattern in request:
                    alerts.append({
                        "type": "SQL Injection",
                        "message":Fore.RED + f"Suspicious SQL pattern found in request: {request}"
                    })
                    break

        return alerts

    def detect_rdp_activity(self):
        """Detect suspicious RDP-related activity.

        Returns:
            list: List of suspicious RDP alerts.
        """
        alerts = []

        for log in self.logs:
            event_type = log.get("event_type", "").lower()

            if "rdp" in event_type:
                alerts.append({
                    "type": "Suspicious RDP Activity",
                    "message": Fore.RED + f"RDP-related event detected from IP: {log.get('ip', 'Unknown')}"
                })

        return alerts

    def detect_powershell_activity(self):
        """Detect suspicious PowerShell activity in requests.

        Returns:
            list: List of suspicious PowerShell activity alerts.
        """
        alerts = []
        suspicious_keywords = ["powershell", "invoke-webrequest", "downloadstring", ".ps1"]

        for log in self.logs:
            request = log.get("request", "").lower()

            for keyword in suspicious_keywords:
                if keyword in request:
                    alerts.append({
                        "type": "Suspicious PowerShell Activity",
                        "message":Fore.RED + f"Suspicious PowerShell command found: {request}"
                    })
                    break

        return alerts

    def detect_malicious_file_download(self):
        """Detect suspicious file downloads.

        Returns:
            list: List of suspicious file download alerts.
        """
        alerts = []
        suspicious_extensions = [".exe", ".bat", ".dll", ".ps1"]

        for log in self.logs:
            request = log.get("request", "").lower()

            for extension in suspicious_extensions:
                if extension in request:
                    alerts.append({
                        "type": "Suspicious File Download",
                        "message":Fore.RED + f"Suspicious file detected in request: {request}"
                    })
                    break

        return alerts

    def detect_brute_force(self):
        """Detect possible brute force login attempts.

        Returns:
            list: List of brute force attack alerts.
        """
        ip_fail_counter = {}

        for log in self.logs:
            if log.get("event_type") == "login_failed":
                ip = log.get("ip")

                if ip not in ip_fail_counter:
                    ip_fail_counter[ip] = 0

                ip_fail_counter[ip] += 1

        alerts = []

        for ip, count in ip_fail_counter.items():
            if count >= 5:
                alerts.append({
                    "type": "Brute Force Attack",
                    "message":Fore.RED + f"Multiple failed login attempts detected from IP {ip} ({count} attempts)"
                })

        return alerts

    def detect_suspicious_powershell_commands(self):
        """Detect suspicious PowerShell commands often used in attacks.

        Returns:
            list: List of suspicious PowerShell command alerts.
        """
        suspicious_keywords = [
            "encodedcommand",
            "downloadstring",
            "invoke-webrequest",
            "iex",
            "bypass"
        ]

        alerts = []

        for log in self.logs:
            command = str(log.get("command", "")).lower()

            for keyword in suspicious_keywords:
                if keyword in command:
                    alerts.append({
                        "type": "Suspicious PowerShell Command",
                        "severity": "High",
                        "message": Fore.RED + f"Suspicious PowerShell command detected: {keyword}"
                    })
                    break

        return alerts

    def run_all_rules(self):
        """Run all detection rules and combine all generated alerts.

        Returns:
            list: Combined list of all detected alerts.
        """
        all_alerts = []
        all_alerts.extend(self.detect_brute_force())
        all_alerts.extend(self.detect_sql_injection())
        all_alerts.extend(self.detect_rdp_activity())
        all_alerts.extend(self.detect_powershell_activity())
        all_alerts.extend(self.detect_suspicious_powershell_commands())
        all_alerts.extend(self.detect_malicious_file_download())

        return all_alerts