from colorama import Fore,init
import json
import os
import time

init(autoreset=True)

class User:
    """Represent a generic user in the MANEE' Security System.

    Args:
        user_id (int): Unique user ID.
        user_name (str) : user name 
        email (str): User email address.
        password (str): User password.
        role (str): User role in the system.
    """

    def __init__(self, user_id: int, user_name:str, email: str, password: str, role: str):
        self.user_id = user_id
        self.email = email
        self.password = password
        self.role = role
        self.user_name=user_name


    def show_menu(self):
        """Return the menu for the current user.

        Raises:
            NotImplementedError: If the child class does not implement this method.
        """
        raise NotImplementedError(Fore.RED +"Each user type must implement its own menu.")


class Admin(User):
    """Represent an admin user."""

    def __init__(self, user_id: int,user_name:str, email: str, password: str):
        super().__init__(user_id,user_name, email, password, "admin")

    def show_menu(self):
        """Return the admin menu.

        Returns:
            str: Admin menu text.
        """

        return """
Admin Menu
1 - Ticket Management
2 - Dashboard
3 - Exit

Select option: >
"""


class Employee(User):
    """Represent an employee user."""

    def __init__(self, user_id: int,user_name:str, email: str, password: str):
        super().__init__(user_id,user_name, email, password, "employee")

    def show_menu(self):
        """Return the employee menu.

        Returns:
            str: Employee menu text.
        """
        return """
Employee Menu
1 - Analyze Log
2 - Create Ticket
3 - View My Tickets
4 - Exit

Select option: >
"""


class AuthService:
    """Handle authentication operations for SecureDesk users.

    Args:
        users_file (str): Relative path to the users JSON file.
    """

    def __init__(self, users_file: str):
        project_dir = os.path.dirname(os.path.dirname(__file__))
        self.users_file = os.path.join(project_dir, users_file)

    def load_users(self):
        """Load users from the JSON file.

        Returns:
            list: A list of user dictionaries.

        Raises:
            FileNotFoundError: If the users file does not exist.
            ValueError: If the users file contains invalid JSON.
        """
        try:
            with open(self.users_file, "r", encoding="utf-8") as file:
                return json.load(file)
        except FileNotFoundError:
            raise FileNotFoundError(Fore.RED + f"Users file not found: {self.users_file}")
        except json.JSONDecodeError:
            raise ValueError(Fore.RED + "Users file contains invalid JSON.")

    def login(self):
        """Authenticate a user with limited login attempts.

        The user has 3 attempts to enter valid credentials.
        If all attempts fail, the login is blocked for 5 minutes.

        Returns:
            Admin | Employee: A logged-in user object.

        Raises:
            ValueError: If login fails after the allowed attempts.
        """
        max_attempts = 3
        attempts = 0

        users = self.load_users()

        while attempts < max_attempts:
            email = input(Fore.CYAN +"Enter your email: ").strip()
            password = input(Fore.CYAN +"Enter your password: ").strip()

            for user in users:
                if user["email"] == email and user["password"] == password:
                    if user["role"] == "admin":
                        return Admin(
                            user["id"],
                            user["user_name"],
                            user["email"],
                            user["password"]
            )

                    elif user["role"] == "employee":
                        return Employee(
                            user["id"],
                            user["user_name"],
                            user["email"],
                            user["password"]
            )
                    else:
                        raise ValueError(Fore.RED + "Unknown user role found in users file.")

            attempts += 1
            print(Fore.RED + f"\nInvalid email or password. Attempt {attempts}/{max_attempts}\n")

        print(Fore.RED + "Too many failed login attempts.")
        print(Fore.RED + "Please try again after 5 minutes.\n")
        time.sleep(1)

        raise ValueError(Fore.RED + "Login temporarily blocked for 5 minutes.")