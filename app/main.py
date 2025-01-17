import json
import os
import re

from rich.console import Console
from rich.align import Align
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.box import ROUNDED

console = Console()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_JSON_FILE_PATH = os.path.join(BASE_DIR, "user_data", "users.json")


def show_banner():
    banner = """ ____                 ____  _        _   
|  _ \  ___  ___ _ __/ ___|| |_ __ _| |_ 
| | | || _ \| _ \ '__\___ \| __/ _` | __|
| |_| |  __/  __/ |   ___) | || (_| | |_ 
|____/ \___|\___|_|  |____/ \__\__,_|\__|
"""
    centered_banner = Align.center(banner, vertical="middle")
    console.print(centered_banner, style="bold green")


def show_menu(menu_name="user_actions"):
    menus = {
        "auth": {
            "items": [
                "[1] 🔐 Sign in",
                "[2] 📝 Sign up",
                "[3] ♻️  Reset password",
                "[0]🚪 Exit",
            ],
            "header": "User Authentication Menu",
        },
        "user_actions": {
            "items": [
                "[1] 📋 Display data",
                "[2] 📊 Statistical analysis",
                "[3] 🔎 Data search",
                "[0]🚪 Exit",
            ],
            "header": "Data Management Menu",
        },
    }
    menu_data = menus.get(menu_name, {})
    menu_items = menu_data.get("items", [])
    header_menu = menu_data.get("header", "Menu")
    if not menu_items:
        show_message("error", "Menu not found!")
        return None
    console.print(Align.center(header_menu, style="bold"))
    table = Table(
        show_header=False, expand=False, box=ROUNDED, pad_edge=True, style="dim grey70"
    )
    table.add_row(*menu_items)
    console.print(Align.center(table, vertical="middle"))
    return input("\n 🛎️  Enter your number choice: [ ]\033[12;32H")


def show_header(menu_name="user_actions"):
    console.clear()
    show_banner()
    choice = show_menu(menu_name)
    return choice


def show_message(type, message):
    panel_types = {
        "error": {"icon": "❌", "title": "[bold]Error[/bold]", "color": "#FF6F61"},
        "warning": {"icon": "⚠️", "title": "[bold]Warning[/bold]", "color": "#FFA726"},
        "success": {"icon": "🎉", "title": "[bold]Success[/bold]", "color": "#66BB6A"},
        "info": {"icon": "ℹ️", "title": "[bold]Info[/bold]", "color": "#42A5F5"},
    }
    default_type = "info"
    selected_type = panel_types.get(type, panel_types[default_type])
    console.print("\n")
    console.print(
        Panel(
            f"{message}",
            title=f"{selected_type['icon']}  {selected_type['title']}",
            style=selected_type["color"],
        )
    )
    input(" Press enter key to continue ...")


def show_process_progress(emoji, process_type, fields):
    table = Table(
        show_header=True,
        header_style="bold",
        box=ROUNDED,
        pad_edge=True,
        style="dim grey70",
    )

    table.add_column("Field", justify="center")
    table.add_column("Value", justify="center")
    table.add_column("Status", justify="center")

    index = 0
    for field, value in fields.items():
        status = "✅" if value else "❌"
        display_value = (
            "*" * len(value)
            if "password" in field.lower() and value
            else (value or "None")
        )
        table.add_row(field, display_value, status)
        if index < len(fields) - 1:
            table.add_row()
        index += 1

    console.clear()
    show_banner()
    aligned_table = Align.center(table, vertical="middle")
    console.print(Align.center(f"{emoji} {process_type} Progress"), style="bold")
    console.print(aligned_table)


def write_json_file(data):
    with open(USERS_JSON_FILE_PATH, "w") as file:
        json.dump(data, file, indent=4)


def read_json_file():
    if not os.path.exists(USERS_JSON_FILE_PATH):
        with open(USERS_JSON_FILE_PATH, "w") as file:
            json.dump({}, file)
    with open(USERS_JSON_FILE_PATH, "r") as file:
        return json.load(file)


def find_user(username):
    users = read_json_file()
    return users.get(username, None)


def save_user(username, password, email):
    users = read_json_file()
    users[username] = {"password": password, "email": email}
    write_json_file(users)


def is_username_unique(username):
    user = find_user(username)
    return user is None


def validate_username(
    username,
    min_length=3,
    max_length=15,
    check_valid_chars=True,
    check_uniqueness=True,
    check_length=True,
):
    if not username:
        return "Username cannot be empty."
    if check_length and len(username) < min_length:
        return f"Username must be at least {min_length} characters long."
    if check_length and len(username) > max_length:
        return f"Username cannot exceed {max_length} characters."
    if check_valid_chars and not re.fullmatch("^[A-Za-z0-9_-]*$", username):
        return "Username can only contain letters, numbers, underscores, hyphens."
    if check_uniqueness and not is_username_unique(username):
        return "Username already exists. Please choose another one."
    return None


def validate_password(
    password, min_length=8, check_length=True, check_confirmation=True
):
    if not password:
        return "Password cannot be empty."
    if check_length and len(password) < min_length:
        return "Password must be at least 8 characters long."
    if check_confirmation and password != Prompt.ask(
        " 🔑 Confirm your password", password=True
    ):
        return "Passwords do not match."
    return None


def is_email_unique(email):
    users = read_json_file()
    for user_data in users.values():
        if user_data["email"] == email:
            return False
    return True


def validate_email(email, check_valid_chars=True, check_uniqueness=True):
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not email:
        return "Email cannot be empty."
    if check_valid_chars and not re.match(email_regex, email):
        return "Invalid email format. Please try again."
    if check_uniqueness and not is_email_unique(email):
        return "This email is already registered. Please use a different one."
    return None


def get_input_with_validation(prompt_text, validator, secure=False):
    value = Prompt.ask(prompt_text, password=secure).strip()
    error = validator(value)
    if error:
        show_message("error", error)
    else:
        return value


def register_user():
    fields = {"👤 Username": None, "🔐 Password": None, "📧 Email": None}
    while not fields["👤 Username"]:
        show_process_progress("📝", "Registration", fields)
        fields["👤 Username"] = get_input_with_validation(
            " 👤 Please enter your desired username", validate_username
        )
    while not fields["🔐 Password"]:
        show_process_progress("📝", "Registration", fields)
        fields["🔐 Password"] = get_input_with_validation(
            " 🔑 Enter a secure password [#FFA500](at least 8 characters)[/#FFA500]",
            validate_password,
            secure=True,
        )
    while not fields["📧 Email"]:
        show_process_progress("📝", "Registration", fields)
        fields["📧 Email"] = get_input_with_validation(
            " 📧 Enter your email address", validate_email
        )
    show_process_progress("📝", "Registration", fields)
    confirmation = Prompt.ask(
        " 🤝 Do you want to proceed with the registration?", choices=["yes", "no"]
    )
    if confirmation == "yes":
        save_user(fields["👤 Username"], fields["🔐 Password"], fields["📧 Email"])
        show_message("success", "User registered successfully!")
    else:
        show_message("info", "Registration canceled.")


def authenticate_user(username, password):
    user = find_user(username)
    if user and user["password"] == password:
        return True
    return False


def handle_login_tries(max_tries=3):
    remaining_tries = max_tries
    while remaining_tries > 0:
        fields = {"👤 Username": None, "🔐 Password": None}
        while not fields["👤 Username"]:
            show_process_progress("🔐", "Sign in", fields)
            fields["👤 Username"] = get_input_with_validation(
                " 👤 Please enter your username",
                lambda username: validate_username(
                    username,
                    check_length=False,
                    check_uniqueness=False,
                    check_valid_chars=False,
                ),
            )
        while not fields["🔐 Password"]:
            show_process_progress("📝", "Registration", fields)
            fields["🔐 Password"] = get_input_with_validation(
                " 🔑 Enter your password to continue",
                lambda password: validate_password(
                    password, check_length=False, check_confirmation=False
                ),
                secure=True,
            )
        if authenticate_user(fields["👤 Username"], fields["🔐 Password"]):
            show_process_progress("🔐", "Sign in", fields)
            return True
        else:
            remaining_tries -= 1
            show_process_progress("🔐", "Sign in", fields)
            message = (
                "All attempts used. If you forgot your password, use the 'Reset Password'."
                if remaining_tries == 0
                else f"Invalid username or password, {remaining_tries} attempt(s) left! Please try again."
            )
            show_message("error", message)
    return False


def login_user():
    if handle_login_tries():
        show_message(
            "success",
            "Welcome back! You have successfully logged in.",
        )
        return True
    else:
        return False


def init():
    while True:
        user_choice = show_header("auth")
        if user_choice == "0":
            console.clear()
            return
        elif user_choice == "1":
            if login_user():
                show_header()
            else:
                console.clear()
                return
        elif user_choice == "2":
            register_user()
        else:
            show_message("error", "Your choice not found!")


init()
