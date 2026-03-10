"""
Ticket Service Module

This module manages security incident tickets in the MANEE' Security
System, including creating, viewing, updating, deleting, and summarizing
tickets.
"""
from colorama import Fore,init
from core.data_storage import DataStorage


init(autoreset=True)

class Ticket:
    """Represent a security ticket in the system.

    Args:
        ticket_id (int): Unique ticket identifier.
        title (str): Ticket title.
        description (str): Ticket description.
        created_by (str): Email of the user who created the ticket.
        severity (str): Severity level of the incident.
        recommendation (str): Recommended action for the incident.
        status (str, optional): Current ticket status. Defaults to "Open".
    """

    def __init__(
        self,
        ticket_id: int,
        title: str,
        description: str,
        created_by: str,
        severity: str,
        recommendation: str,
        status: str = "Open"
    ):
        self.ticket_id = ticket_id
        self.title = title
        self.description = description
        self.created_by = created_by
        self.severity = severity
        self.recommendation = recommendation
        self.status = status

    def to_dict(self):
        """Convert the ticket object to a dictionary.

        Returns:
            dict: Dictionary representation of the ticket.
        """
        return {
            "ticket_id": self.ticket_id,
            "title": self.title,
            "description": self.description,
            "created_by": self.created_by,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "status": self.status
        }


class TicketService:
    """Provide services for managing security tickets.

    Args:
        storage (DataStorage): Storage handler used for reading and
            writing ticket data.
    """

    def __init__(self, storage: DataStorage):
        """Initialize the ticket service.

        Args:
            storage (DataStorage): Storage object for ticket persistence.
        """
        self.storage = storage

    def create_ticket(self, current_user):
        """Create a normal ticket manually.

        Args:
            current_user: The currently logged-in user.

        Raises:
            ValueError: If title or description is empty.
        """
        title = input("Enter ticket title: ").strip()
        description = input("Enter ticket description: ").strip()
        severity = input("Enter severity (Low / Medium / High / Critical): ").strip()
        recommendation = input("Enter recommendation: ").strip()

        if not title or not description:
            raise ValueError(Fore.RED +"Title and description cannot be empty.")

        tickets = self.storage.load_tickets()

        if tickets:
            new_id = tickets[-1]["ticket_id"] + 1
        else:
            new_id = 1

        ticket = Ticket(
            ticket_id=new_id,
            title=title,
            description=description,
            created_by=current_user.email,
            severity=severity,
            recommendation=recommendation
        )

        tickets.append(ticket.to_dict())
        self.storage.save_tickets(tickets)

        print(Fore.GREEN +f"\n Ticket created successfully with ID: {new_id}\n")

    def create_ticket_from_report(self, current_user, report_path: str, risk_score: int, threat_level: str):
        """Create a ticket from an existing security report.

        Args:
            current_user: The currently logged-in user.
            report_path (str): Path to the generated report file.
            risk_score (int): Calculated risk score.
            threat_level (str): Calculated threat level.

        Raises:
            ValueError: If title or description is empty.
        """
        title = input("Enter ticket title: ").strip()
        description = input("Enter ticket description: ").strip()
        recommendation = input("Enter recommendation: ").strip()

        if not title or not description:
            raise ValueError(Fore.RED +"Title and description cannot be empty.")

        tickets = self.storage.load_tickets()

        if tickets:
            new_id = tickets[-1]["ticket_id"] + 1
        else:
            new_id = 1

        new_ticket = {
            "ticket_id": new_id,
            "title": title,
            "description": description,
            "created_by": current_user.email,
            "status": "Open",
            "severity": threat_level,
            "recommendation": recommendation,
            "report_path": report_path,
            "risk_score": risk_score,
            "threat_level": threat_level
        }

        tickets.append(new_ticket)
        self.storage.save_tickets(tickets)

        print(Fore.GREEN +f"\n Ticket created successfully from analysis with ID: {new_id}\n")

    def view_all_tickets(self):
        """Display all tickets in the system."""
        tickets = self.storage.load_tickets()

        if not tickets:
            print(Fore.YELLOW +"\nNo tickets found.\n")
            return

        print("\n========== All Tickets ==========")
        for ticket in tickets:
            print(f"ID: {ticket['ticket_id']}")
            print(f"Title: {ticket['title']}")
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
        print()

    def view_my_tickets(self, current_user):
        """Display tickets created by the current user.

        Args:
            current_user: The currently logged-in user.
        """
        tickets = self.storage.load_tickets()
        my_tickets = [ticket for ticket in tickets if ticket["created_by"] == current_user.email]

        if not my_tickets:
            print(Fore.YELLOW +"\nYou have no tickets.\n")
            return

        print("\n========== My Tickets ==========")

        for ticket in my_tickets:
            print(f"ID: {ticket['ticket_id']}")
            print(f"Title: {ticket['title']}")
            print(f"Status: {ticket['status']}")

            if "severity" in ticket:
                print(f"Severity: {ticket['severity']}")

            if "recommendation" in ticket:
                print(f"Recommendation: {ticket['recommendation']}")

            if "risk_score" in ticket:
                print(f"Risk Score: {ticket['risk_score']}")

            if "threat_level" in ticket:
                print(f"Threat Level: {ticket['threat_level']}")

            if "report_path" in ticket:
                print(f"Report Path: {ticket['report_path']}")

            print("-" * 30)

        print()

    def search_ticket_by_id(self, ticket_id: int):
        """Search for a ticket by its ID.

        Args:
            ticket_id (int): Ticket ID to search for.

        Returns:
            dict: Matching ticket data.

        Raises:
            ValueError: If the ticket is not found.
        """
        tickets = self.storage.load_tickets()

        for ticket in tickets:
            if ticket["ticket_id"] == ticket_id:
                return ticket

        raise ValueError(Fore.YELLOW +f"Ticket with ID {ticket_id} not found.")

    def delete_ticket(self, ticket_id: int):
        """Delete a ticket by its ID.

        Args:
            ticket_id (int): Ticket ID to delete.

        Raises:
            ValueError: If the ticket is not found.
        """
        tickets = self.storage.load_tickets()

        for ticket in tickets:
            if ticket["ticket_id"] == ticket_id:
                tickets.remove(ticket)
                self.storage.save_tickets(tickets)
                print(Fore.GREEN +f"\n Ticket ID {ticket_id} deleted successfully.\n")
                return

        raise ValueError(Fore.YELLOW +f"Ticket with ID {ticket_id} not found.")

    def change_ticket_status(self, ticket_id: int, new_status: str):
        """Change the status of an existing ticket.

        Args:
            ticket_id (int): Ticket ID to update.
            new_status (str): New status value.

        Raises:
            ValueError: If the status is invalid or the ticket is not found.
        """
        tickets = self.storage.load_tickets()

        valid_statuses = ["Open", "In Progress", "Closed"]

        if new_status not in valid_statuses:
            raise ValueError(Fore.RED +"Invalid status. Choose: Open, In Progress, or Closed.")

        for ticket in tickets:
            if ticket["ticket_id"] == ticket_id:
                ticket["status"] = new_status
                self.storage.save_tickets(tickets)
                print(Fore.GREEN +f"\n Ticket ID {ticket_id} status updated to {new_status}.\n")
                return

        raise ValueError(Fore.YELLOW +f"Ticket with ID {ticket_id} not found.")

    def dashboard_summary(self):
        """Display a simple dashboard summary for the admin."""
        tickets = self.storage.load_tickets()

        total_tickets = len(tickets)
        open_tickets = 0
        closed_tickets = 0
        critical_tickets = 0

        for ticket in tickets:
            status = ticket.get("status", "")
            severity = ticket.get("severity", "")

            if status == "Open":
                open_tickets += 1

            if status == "Closed":
                closed_tickets += 1

            if severity == "Critical":
                critical_tickets += 1

        print(Fore.CYAN +"\n========== Admin Dashboard ==========")
        print(f"Total Tickets   : {total_tickets}")
        print(f"Open Tickets    : {open_tickets}")
        print(f"Closed Tickets  : {closed_tickets}")
        print(f"Critical Tickets: {critical_tickets}")
        print(Fore.CYAN +"=====================================\n")