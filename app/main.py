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


def show_registration_progress(username, password, email):
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
    table.add_row("👤 Username", str(username or "None"), "✅" if username else "❌")
    table.add_row()
    table.add_row(
        "🔐 Password",
        ("*" * len(password) if password else "None"),
        "✅" if password else "❌",
    )
    table.add_row()
    table.add_row("📧 Email", str(email or "None"), "✅" if email else "❌")
    console.clear()
    show_banner()
    aligned_table = Align.center(table, vertical="middle")
    console.print(Align.center("📝 Registration Progress"), style="bold")
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


def validate_username(username):
    if not username:
        return "Username cannot be empty."
    if " " in username:
        return "Username cannot contain spaces."
    if find_user(username):
        return "Username already exists. Please choose another one."
    return None


def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if password != Prompt.ask(" 🔑 Confirm your password", password=True):
        return "Passwords do not match."
    return None


def validate_email(email):
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not email:
        return "Email cannot be empty."
    if not re.match(email_regex, email):
        return "Invalid email format. Please try again."
    return None


def get_input_with_validation(prompt_text, validator, secure=False):
    value = Prompt.ask(prompt_text, password=secure).strip()
    error = validator(value)
    if error:
        show_message("error", error)
    else:
        return value


def register_user():
    username, password, email = None, None, None
    while not username:
        show_registration_progress(username, password, email)
        username = get_input_with_validation(
            " 👤 Please enter your desired username", validate_username
        )
    while not password:
        show_registration_progress(username, password, email)
        password = get_input_with_validation(
            " 🔑 Enter a secure password [#FFA500](at least 8 characters)[/#FFA500]",
            validate_password,
            secure=True,
        )
    while not email:
        show_registration_progress(username, password, email)
        email = get_input_with_validation(
            " 📧 Enter your email address", validate_email
        )
    show_registration_progress(username, password, email)
    confirmation = Prompt.ask(
        " 🤝 Do you want to proceed with the registration?", choices=["yes", "no"]
    )
    if confirmation == "yes":
        save_user(username, password, email)
        show_message("success", "User registered successfully!")
    else:
        show_message("info", "Registration canceled.")


def init():
    while True:
        user_choice = show_header("auth")
        if user_choice == "0":
            console.clear()
            return
        elif user_choice == "2":
            register_user()
        else:
            show_message("error", "Your choice not found!")


init()
