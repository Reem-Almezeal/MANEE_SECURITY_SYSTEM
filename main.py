"""
MANEE' Security System - Main Application

This module is the entry point of the MANEE' Security System.

It manages:
- User authentication
- Role-based access (Admin / Employee)
- System navigation and user interaction

The system allows employees to analyze log files, detect security
threats, generate reports, and create security tickets.
Administrators can review and manage security tickets.

"""
from colorama import Fore,init
import os
from dotenv import load_dotenv
from core.auth import AuthService
from core.data_storage import DataStorage
from core.ticket_service import TicketService
from core.log_loader import LogLoader
from core.log_analyzer import LogAnalyzer
from core.detection_rules import DetectionRules
from core.risk_engine import RiskEngine
from core.report_service import ReportService



init(autoreset=True)
load_dotenv()

print()
print("======================================================")
print(Fore.CYAN +"        Welcome To MANEE' Security System")
print("======================================================")
print()

menu = """
1 - Login
2 - Help
3 - Exit

Select option: >
"""

# Initialize system services
auth_service = AuthService(os.getenv("USERS_FILE"))
storage = DataStorage(os.getenv("TICKETS_FILE"))
ticket_service = TicketService(storage)
report_service = ReportService()

while True:
    user_choice = input(menu).strip()

    match user_choice:
        case "1":
            try:
                # Authenticate user
                current_user = auth_service.login()
                print(f"\nWelcome Back {current_user.user_name}")

                while True:
                    sub_choice = input(current_user.show_menu()).strip()

                    # =====================================
                    # Admin Menu Logic
                    # =====================================
                    if current_user.role == "admin":
                        if sub_choice == "1":
                            while True:
                                ticket_menu = """
Ticket Management
1 - View All Tickets
2 - Search Ticket By ID
3 - Change Ticket Status
4 - Delete Ticket
5 - Back

Select option: >
"""
                                ticket_choice = input(ticket_menu).strip()

                                try:
                                    if ticket_choice == "1":
                                        ticket_service.view_all_tickets()

                                    elif ticket_choice == "2":
                                        ticket_id = int(input("Enter ticket ID: ").strip())
                                        ticket = ticket_service.search_ticket_by_id(ticket_id)

                                        print(Fore.CYAN +"\n========== Ticket Details ==========")
                                        print(f"ID: {ticket['ticket_id']}")
                                        print(f"Title: {ticket['title']}")
                                        print(f"Description: {ticket['description']}")
                                        print(f"Created By: {ticket['created_by']}")
                                        print(f"Status: {ticket['status']}")

                                        if "severity" in ticket:
                                            print(f"Severity: {ticket['severity']}")

                                        if "recommendation" in ticket:
                                            print(f"Recommendation: {ticket['recommendation']}")

                                        if "threat_level" in ticket:
                                            print(f"Threat Level: {ticket['threat_level']}")

                                        if "risk_score" in ticket:
                                            print(f"Risk Score: {ticket['risk_score']}")

                                        if "report_path" in ticket:
                                            print(f"Report Path: {ticket['report_path']}")

                                        print("-" * 30)

                                    elif ticket_choice == "3":
                                        ticket_id = int(input("Enter ticket ID: ").strip())
                                        new_status = input(
                                            "Enter new status (Open / In Progress / Closed): "
                                        ).strip()

                                        ticket_service.change_ticket_status(ticket_id, new_status)

                                    elif ticket_choice == "4":
                                        ticket_id = int(input("Enter ticket ID to delete: ").strip())
                                        ticket_service.delete_ticket(ticket_id)

                                    elif ticket_choice == "5":
                                        print("\nReturning to Admin Menu...\n")
                                        break

                                    else:
                                        print(Fore.YELLOW + "\nPlease choose a valid option.\n")

                                except ValueError as error:
                                    print(Fore.RED + f"\nError: {error}\n")
                                except Exception as error:
                                    print(Fore.RED + f"\nUnexpected Error: {error}\n")

                        elif sub_choice == "2":
                            ticket_service.dashboard_summary()

                        elif sub_choice == "3":
                            print("\nReturning to main menu...\n")
                            break

                        else:
                            print(Fore.YELLOW + "\nPlease choose a valid option.\n")

                    # =====================================
                    # Employee Menu Logic
                    # =====================================
                    elif current_user.role == "employee":
                        if sub_choice == "1":
                            try:
                                # Load log file
                                file_path = input("Enter log file path: ").strip()
                                loader = LogLoader(file_path)
                                logs = loader.load_logs()

                                # Analyze logs
                                analyzer = LogAnalyzer(logs)
                                summary = analyzer.analyze_summary()

                                # Detect threats
                                rules = DetectionRules(logs)
                                alerts = rules.run_all_rules()

                                # Calculate risk score
                                risk_engine = RiskEngine(alerts)
                                risk_score = risk_engine.calculate_score()
                                threat_level = risk_engine.get_threat_level()

                                print(Fore.CYAN +"\n========== Log Analysis Summary ==========")
                                print(f"Total Logs: {summary['total_logs']}")

                                print("\nTop IPs:")
                                for ip, count in summary["top_ips"]:
                                    print(f"- {ip}: {count}")

                                print("\nTop Events:")
                                for event, count in summary["top_events"]:
                                    print(f"- {event}: {count}")

                                print(Fore.CYAN +"\n========== Detected Alerts ==========")
                                if alerts:
                                    for index, alert in enumerate(alerts, start=1):
                                        print(f"{index}. {alert['type']}")
                                        print(f"   {alert['message']}")
                                else:
                                    print("No suspicious activity detected.")

                                print(Fore.CYAN +"\n========== Risk Assessment ==========")
                                print(f"Risk Score: {risk_score}")
                                print(f"Threat Level: {threat_level}")
                                print()

                                save_report = input(
                                    "Do you want to save the report? (yes/no): "
                                ).strip().lower()

                                if save_report == "yes":
                                    report_path = report_service.generate_report(
                                        summary,
                                        alerts,
                                        risk_score,
                                        threat_level,
                                        current_user.user_name
                                    )
                                    print(Fore.GREEN + f"\n Report saved successfully at: {report_path}\n")

                                    create_ticket = input(
                                        "Do you want to create a ticket from this analysis? (yes/no): "
                                    ).strip().lower()

                                    if create_ticket == "yes":
                                        ticket_service.create_ticket_from_report(
                                            current_user,
                                            report_path,
                                            risk_score,
                                            threat_level
                                        )
                                    else:
                                        print("\nNo ticket was created from this analysis.\n")

                                else:
                                    print(Fore.YELLOW + "\nReport was not saved.\n")

                            except Exception as error:
                                print(Fore.RED + f"\nError: {error}\n")

                        elif sub_choice == "2":
                            while True:
                                create_ticket_menu = """
Create Ticket
1 - Create Normal Ticket
2 - Create Ticket From Existing Report
3 - Back

Select option: >
"""
                                create_ticket_choice = input(create_ticket_menu).strip()

                                try:
                                    if create_ticket_choice == "1":
                                        ticket_service.create_ticket(current_user)

                                    elif create_ticket_choice == "2":
                                        report_path = input("Enter report file path: ").strip()

                                        if not os.path.exists(report_path):
                                            raise FileNotFoundError(Fore.YELLOW + "Report file not found.")

                                        risk_score = int(input("Enter risk score: ").strip())
                                        if risk_score < 0 or risk_score > 100:
                                            raise ValueError(Fore.RED + "Risk score must be between 0 and 100.")

                                        threat_input = input("Enter threat level (Low / Medium / High / Critical): ").strip().lower()

                                        severity_map = {    "low": "Low",
                                                            "l": "Low",
                                                            "medium": "Medium",
                                                            "m": "Medium",
                                                            "high": "High",
                                                            "h": "High",
                                                            "hight": "High",
                                                            "critical": "Critical",
                                                            "c": "Critical"
                                                        }


                                        if threat_input not in severity_map:
                                            raise ValueError(Fore.RED +  "Invalid threat level. Choose: Low, Medium, High, or Critical.")

                                        threat_level = severity_map[threat_input]
                                        ticket_service.create_ticket_from_report(
                                            current_user,
                                            report_path,
                                            risk_score,
                                            threat_level
                                        )

                                    elif create_ticket_choice == "3":
                                        print("\nReturning to Employee Menu...\n")
                                        break

                                    else:
                                        print(Fore.YELLOW + "\nPlease choose a valid option.\n")

                                except ValueError as error:
                                    print(Fore.RED + f"\nError: {error}\n")
                                except Exception as error:
                                    print(Fore.RED + f"\nError: {error}\n")

                        elif sub_choice == "3":
                            try:
                                ticket_service.view_my_tickets(current_user)
                            except Exception as error:
                                print(Fore.RED + f"\nError: {error}\n")

                        elif sub_choice == "4":
                            print("\nReturning to main menu...\n")
                            break

                        else:
                            print(Fore.YELLOW + "\nPlease choose a valid option.\n")

            except Exception as error:
                print(Fore.RED + f"\nError: {error}\n")

        case "2":
            print("\nMANEE' Security System Help Section\n")
            print("Please contact the MANEE' System Support Team via the email below")
            print("to submit complaints and suggestions:")
            print(Fore.CYAN + "manee@gmail.com\n")

        case "3":
            print(Fore.CYAN +"\nLogging out...")
            print(Fore.CYAN +"Closing MANEE' Security System...")
            print(Fore.CYAN +"See you soon....")
            break

        case _:
            print(Fore.YELLOW + "\nPlease choose a valid option.\n")